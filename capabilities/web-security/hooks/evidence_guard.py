"""Track exploit proof evidence and challenge unsupported confirmations."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any

try:
    import dreadnode as dn
except Exception:  # pragma: no cover - import shim for isolated hook tests
    dn = None  # type: ignore[assignment]

from dreadnode.agents.events import AgentEnd, GenerationStep, ToolEnd
from dreadnode.agents.reactions import Continue
from dreadnode.core.hook import hook

_MAX_TEXT_CHARS = 2000
_MAX_EVIDENCE_PER_AGENT = 100
_STATE_LOCK = asyncio.Lock()

_XSS_TERMS = re.compile(
    r"\b(xss|cross[- ]site scripting|javascript execution|script execution|browser js execution)\b",
    re.IGNORECASE,
)
_BLIND_XSS_TERMS = re.compile(
    r"\b(blind\s+xss|out[- ]of[- ]band\s+xss|oob\s+xss|xss\s+callback)\b",
    re.IGNORECASE,
)
_SSRF_TERMS = re.compile(
    r"\b(ssrf|server[- ]side request forgery|out[- ]of[- ]band|oob callback)\b",
    re.IGNORECASE,
)
_CONFIRMED_TERMS = re.compile(
    r"\b(confirmed|verified|proved|proven|executed|exploited|triggered|vulnerable)\b",
    re.IGNORECASE,
)
_HEDGED_TERMS = re.compile(
    r"\b(need to|will|should|might|may|potential|possible|attempt|try|not confirmed|unconfirmed)\b",
    re.IGNORECASE,
)


@dataclass(slots=True)
class EvidenceRecord:
    kind: str
    status: str
    source: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class AgentEvidenceState:
    records: list[EvidenceRecord] = field(default_factory=list)
    challenged_claims: int = 0

    def add(self, record: EvidenceRecord) -> None:
        self.records.append(record)
        if len(self.records) > _MAX_EVIDENCE_PER_AGENT:
            self.records = self.records[-_MAX_EVIDENCE_PER_AGENT:]

    def has_confirmed(self, kind: str) -> bool:
        return any(
            record.kind == kind and record.status == "confirmed"
            for record in self.records
        )

    def has_issued(self, kind: str) -> bool:
        return any(
            record.kind == kind and record.status in {"issued", "confirmed"}
            for record in self.records
        )

    def summary(self) -> dict[str, Any]:
        counts: dict[str, dict[str, int]] = {}
        for record in self.records:
            counts.setdefault(record.kind, {})
            counts[record.kind][record.status] = (
                counts[record.kind].get(record.status, 0) + 1
            )
        return {"records": len(self.records), "counts": counts}


_AGENT_STATE: dict[str, AgentEvidenceState] = {}


def _compact_text(value: object | None, max_chars: int = _MAX_TEXT_CHARS) -> str:
    if value is None:
        return ""
    text = " ".join(str(value).split()).strip()
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 3].rstrip()}..."


def _tool_name(event: ToolEnd) -> str:
    return str(getattr(event.tool_call, "name", "") or "")


def _parse_tool_result(result: object | None) -> object | None:
    if result is None:
        return None
    if isinstance(result, dict | list):
        return result
    if not isinstance(result, str):
        return result
    text = result.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return result


def _drop_empty(value: object) -> object:
    if isinstance(value, dict):
        return {
            key: cleaned
            for key, item in value.items()
            if (cleaned := _drop_empty(item)) not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [
            cleaned
            for item in value
            if (cleaned := _drop_empty(item)) not in (None, "", [], {})
        ]
    return value


def _log_evidence(agent_id: str, record: EvidenceRecord) -> None:
    if dn is None or not hasattr(dn, "log_output"):
        return
    payload = _drop_empty(
        {
            "agent_id": agent_id,
            "kind": record.kind,
            "status": record.status,
            "source": record.source,
            "detail": record.detail,
        }
    )
    try:
        dn.log_output("web_security_evidence", payload)
    except Exception:
        # Hooks should never fail the run because telemetry is unavailable.
        return


def _extract_assistant_text(event: GenerationStep) -> str:
    if not event.messages:
        return ""
    last_message = event.messages[-1]
    if getattr(last_message, "role", None) != "assistant":
        return ""
    if getattr(last_message, "tool_calls", None):
        return ""
    return _compact_text(getattr(last_message, "content", None), max_chars=4000)


def _claimed_confirmed_kind(text: str) -> str | None:
    if not text or not _CONFIRMED_TERMS.search(text):
        return None
    if _HEDGED_TERMS.search(text):
        return None
    if _BLIND_XSS_TERMS.search(text):
        return "network_callback"
    if _XSS_TERMS.search(text):
        return "browser_js_execution"
    if _SSRF_TERMS.search(text):
        return "network_callback"
    return None


def _browser_js_record(tool_name: str, parsed: object) -> EvidenceRecord | None:
    if isinstance(parsed, dict):
        kind = parsed.get("kind")
        verdict = parsed.get("verdict")
        evidence = parsed.get("evidence")
        reason = _compact_text(parsed.get("reason"), max_chars=500).lower()
        looks_like_js_proof = kind == "browser_js_execution" or (
            parsed.get("verified") is True
            and verdict == "CONFIRMED"
            and (
                "javascript" in reason
                or "browser" in reason
                or isinstance(evidence, list)
            )
        )
        if looks_like_js_proof:
            detail = {
                "proof_id": parsed.get("proof_id") or parsed.get("label"),
                "url": parsed.get("url"),
                "verdict": verdict,
                "confidence": parsed.get("confidence"),
                "reason": parsed.get("reason"),
                "evidence_count": len(evidence) if isinstance(evidence, list) else None,
                "tool": tool_name,
            }
            if parsed.get("verified") is True and verdict == "CONFIRMED":
                return EvidenceRecord(
                    "browser_js_execution",
                    "confirmed",
                    "structured_proof",
                    detail,
                )
            if tool_name.endswith("agent_browser_start_js_execution_proof"):
                return EvidenceRecord(
                    "browser_js_execution",
                    "issued",
                    "agent-browser",
                    detail,
                )
            if tool_name.endswith("agent_browser_reset_js_execution_proof"):
                return EvidenceRecord(
                    "browser_js_execution",
                    "reset",
                    "agent-browser",
                    detail,
                )
            return EvidenceRecord(
                "browser_js_execution",
                "checked",
                "structured_proof",
                detail,
            )

    if not tool_name.endswith(
        (
            "agent_browser_start_js_execution_proof",
            "agent_browser_check_js_execution_proof",
            "agent_browser_reset_js_execution_proof",
        )
    ):
        return None
    if not isinstance(parsed, dict):
        return None

    source = "agent-browser"
    proof_id = parsed.get("proof_id")
    detail = {
        "proof_id": proof_id,
        "url": parsed.get("url"),
        "verdict": parsed.get("verdict"),
        "confidence": parsed.get("confidence"),
        "reason": parsed.get("reason"),
        "evidence_count": len(parsed.get("evidence", []))
        if isinstance(parsed.get("evidence"), list)
        else None,
    }

    if tool_name.endswith("agent_browser_start_js_execution_proof"):
        return EvidenceRecord("browser_js_execution", "issued", source, detail)
    if tool_name.endswith("agent_browser_reset_js_execution_proof"):
        return EvidenceRecord("browser_js_execution", "reset", source, detail)
    if parsed.get("verified") is True and parsed.get("verdict") == "CONFIRMED":
        return EvidenceRecord("browser_js_execution", "confirmed", source, detail)
    return EvidenceRecord("browser_js_execution", "checked", source, detail)


def _callback_record(tool_name: str, parsed: object) -> EvidenceRecord | None:
    if isinstance(parsed, dict) and parsed.get("kind") == "network_callback":
        detail = {
            "url": parsed.get("url"),
            "verdict": parsed.get("verdict"),
            "confidence": parsed.get("confidence"),
            "reason": parsed.get("reason"),
            "tool": tool_name,
        }
        if parsed.get("verified") is True or parsed.get("observed") is True:
            return EvidenceRecord(
                "network_callback",
                "confirmed",
                "structured_proof",
                detail,
            )
        if parsed.get("status") in {"issued", "armed"}:
            return EvidenceRecord(
                "network_callback",
                "issued",
                "structured_proof",
                detail,
            )
        return EvidenceRecord(
            "network_callback",
            "checked",
            "structured_proof",
            detail,
        )

    if not tool_name.endswith(("get_callback_url", "check_callbacks")):
        return None
    text = _compact_text(parsed, max_chars=1200)

    if tool_name.endswith("get_callback_url"):
        if "Error:" in text:
            return EvidenceRecord(
                "network_callback",
                "error",
                "callback",
                {"summary": text},
            )
        return EvidenceRecord(
            "network_callback",
            "issued",
            "callback",
            {"summary": text},
        )

    if re.search(r"\bReceived\s+[1-9]\d*\s+callback interactions?\b", text):
        return EvidenceRecord(
            "network_callback",
            "confirmed",
            "callback",
            {"summary": text},
        )
    if "No callback interactions" in text or "No new callback interactions" in text:
        return EvidenceRecord(
            "network_callback",
            "checked",
            "callback",
            {"summary": text},
        )
    return None


def _media_record(tool_name: str, parsed: object) -> EvidenceRecord | None:
    if not tool_name.endswith(
        ("log_image_output", "log_audio_output", "log_video_output")
    ):
        return None
    detail: dict[str, Any] = {}
    if isinstance(parsed, dict):
        detail = {
            "name": parsed.get("name"),
            "path": parsed.get("path"),
            "kind": parsed.get("kind"),
        }
    else:
        detail = {"summary": _compact_text(parsed, max_chars=500)}
    return EvidenceRecord("media", "attached", "media_logging", detail)


def _records_from_tool_end(event: ToolEnd) -> list[EvidenceRecord]:
    if event.error:
        return []
    name = _tool_name(event)
    parsed = _parse_tool_result(event.result)
    records = [
        _browser_js_record(name, parsed),
        _callback_record(name, parsed),
        _media_record(name, parsed),
    ]
    return [record for record in records if record is not None]


def _proof_feedback(kind: str, state: AgentEvidenceState) -> str:
    if kind == "browser_js_execution":
        if state.has_issued(kind):
            return (
                "You claimed browser JavaScript/XSS execution is confirmed, but this session has no "
                "confirmed browser_js_execution proof. Run `agent_browser_check_js_execution_proof` "
                "for the armed canary and only report CONFIRMED if it returns `verified: true` and "
                "`verdict: CONFIRMED`. Treat reflection, API echoes, DOM presence, and screenshots as "
                "supporting evidence, not execution proof."
            )
        return (
            "You claimed browser JavaScript/XSS execution is confirmed, but this session has no "
            "browser_js_execution proof. Use `agent_browser_start_js_execution_proof`, adapt the "
            "returned token payload to the suspected sink, trigger it in agent-browser, then check it "
            "with `agent_browser_check_js_execution_proof` before reporting confirmation. This applies "
            "to reflected, stored, DOM, and mutation XSS when execution happens in this browser session. "
            "Treat "
            "reflection, API echoes, DOM presence, and screenshots as supporting evidence, not "
            "execution proof. For blind XSS, use callback evidence instead."
        )

    return (
        "You claimed a blind XSS or out-of-band callback vulnerability is confirmed, but this "
        "session has no observed network_callback proof. Use `get_callback_url` before the payload and "
        "`check_callbacks` after triggering it; only treat received callback interactions as proof."
    )


@hook(ToolEnd)
async def record_web_security_evidence(event: ToolEnd) -> None:
    """Record structured proof events from web-security tools."""
    records = _records_from_tool_end(event)
    if not records:
        return

    async with _STATE_LOCK:
        state = _AGENT_STATE.setdefault(event.agent_id, AgentEvidenceState())
        for record in records:
            state.add(record)
            _log_evidence(event.agent_id, record)


@hook(GenerationStep)
async def challenge_unverified_exploit_claim(event: GenerationStep) -> Continue | None:
    """Feed back when a confirmed exploit claim lacks objective proof evidence."""
    assistant_text = _extract_assistant_text(event)
    claimed_kind = _claimed_confirmed_kind(assistant_text)
    if claimed_kind is None:
        return None

    async with _STATE_LOCK:
        state = _AGENT_STATE.setdefault(event.agent_id, AgentEvidenceState())
        if state.has_confirmed(claimed_kind):
            return None
        if state.challenged_claims >= 3:
            return None
        state.challenged_claims += 1
        feedback = _proof_feedback(claimed_kind, state)

    return Continue(feedback=feedback)


@hook(AgentEnd)
async def clear_evidence_state(event: AgentEnd) -> None:
    """Emit a compact proof summary and drop per-agent state at run end."""
    async with _STATE_LOCK:
        state = _AGENT_STATE.pop(event.agent_id, None)

    if state is None:
        return
    if dn is None or not hasattr(dn, "log_output"):
        return
    try:
        dn.log_output("web_security_evidence_summary", state.summary())
    except Exception:
        return
