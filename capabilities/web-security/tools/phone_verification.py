"""Phone verification for auth flows during web security testing.

Two-tier approach:
  1. Free public numbers — scrape receive-smss.com for available numbers,
     read their shared inboxes, extract verification codes. No auth needed.
     Agent can self-serve immediately.
  2. Paid private numbers — SMS-Activate compatible API (sms-man, 5sim,
     sms-activate, etc.) for when targets block known public numbers.
     Requires API key via store_credential.

The agent should always try free numbers first. Fall back to paid only when
the target application rejects or rate-limits public numbers.
"""

from __future__ import annotations

import json
import re
from html import unescape
from typing import Annotated

import httpx
from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr

# Free provider URL patterns: (homepage, inbox_url_template)
# Inbox template uses {number} placeholder (digits only, no +).
_FREE_PROVIDERS = {
    "receive-smss": {
        "homepage": "https://receive-smss.com/",
        "inbox": "https://receive-smss.com/sms/{number}/",
        "notes": "40+ numbers, multi-country, most reliable scrape target.",
    },
    "quackr": {
        "homepage": "https://quackr.io/temporary-numbers",
        "inbox": "https://quackr.io/temporary-numbers/{number}",
        "notes": "30+ countries, JS-rendered (may need fallback).",
    },
    "anonymsms": {
        "homepage": "https://anonymsms.com/",
        "inbox": "https://anonymsms.com/number/{number}/",
        "notes": "US/UK/CA numbers, simple HTML.",
    },
}

_DEFAULT_CODE_REGEX = r"\b\d{4,8}\b"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


def _html_to_text(html: str) -> str:
    """Strip tags, decode entities, collapse whitespace."""
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def _extract_codes(text: str, code_regex: str) -> list[str]:
    """Pull unique code matches from text."""
    seen: set[str] = set()
    codes: list[str] = []
    for match in re.findall(code_regex, text):
        value = match[0] if isinstance(match, tuple) else match
        if value not in seen:
            seen.add(value)
            codes.append(value)
    return codes[:10]


def _parse_numbers_from_html(html: str) -> list[dict[str, str]]:
    """Extract phone numbers and their country from receive-smss.com homepage.

    Real structure (2025):
      <a ... href="/sms/{digits}/" aria-label="+{number} {Country} ...">
        <div class="number-boxes-itemm-number">+{number}</div>
    Country is extracted from the aria-label of the wrapping <a> tag.
    """
    numbers: list[dict[str, str]] = []
    seen: set[str] = set()

    # Primary: aria-label on <a> tags contains both number and country
    for match in re.finditer(
        r'href="/sms/(\d+)/"[^>]*?aria-label="\+?\d[\d\s-]*\s+([^"]*?)\s*(?:temp|receive|sms|online|number|free|verify)[^"]*"',
        html,
        re.IGNORECASE,
    ):
        digits = match.group(1)
        country = match.group(2).strip()
        if digits in seen:
            continue
        seen.add(digits)

        # Get display number from nearby number-boxes-itemm-number div
        after = html[match.end() : match.end() + 500]
        num_match = re.search(r"number-boxes-itemm-number[^>]*>(\+?\d[\d\s-]*)<", after)
        display = re.sub(r"[\s-]", "", num_match.group(1)) if num_match else digits

        numbers.append(
            {
                "number": f"+{display}" if not display.startswith("+") else display,
                "digits": digits,
                "country": country,
                "inbox_url": f"https://receive-smss.com/sms/{digits}/",
            }
        )

    return numbers


def _parse_messages_from_html(html: str) -> list[dict[str, str]]:
    """Extract messages from a receive-smss.com inbox page.

    Real structure (2025):
      <div class="row message_details">
        <div class="col-md-6 msgg">...<span>message body</span></div>
        <div class="col-md-3 senderr">...<a>sender</a></div>
        <div class="col-md-3 time">...time ago</div>
      </div>
    """
    messages: list[dict[str, str]] = []

    # Each message_details block contains 3 col divs, then closes with </div></div>
    # Use a greedy-enough match to capture all inner divs
    for block in re.finditer(
        r'class="row\s+message_details"[^>]*>((?:(?!</div>\s*<div\s+class="row\s+message_details).)*)',
        html,
        re.DOTALL,
    ):
        content = block.group(1)

        body_match = re.search(r'class="[^"]*msgg[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)
        sender_match = re.search(r'class="[^"]*senderr[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)
        time_match = re.search(r'class="[^"]*\btime\b[^"]*"[^>]*>(.*?)</div>', content, re.DOTALL)

        if not body_match:
            continue

        body = _html_to_text(body_match.group(1)).strip()
        # Remove the "Message" label prefix
        body = re.sub(r"^Message\s*", "", body)
        sender = _html_to_text(sender_match.group(1)).strip() if sender_match else "Unknown"
        sender = re.sub(r"^Sender\s*", "", sender)
        time_ago = _html_to_text(time_match.group(1)).strip() if time_match else ""
        time_ago = re.sub(r"^Time\s*", "", time_ago)

        if not body:
            continue

        messages.append(
            {
                "sender": sender,
                "body": body,
                "time": time_ago,
            }
        )

    return messages[:20]


class PhoneVerification(Toolset):
    """Phone verification for signup, recovery, and MFA flows.

    Free public numbers (self-serve, no auth) and paid private numbers
    (SMS-Activate API, requires key). Try free first.
    """

    _http: httpx.AsyncClient | None = PrivateAttr(default=None)

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None or self._http.is_closed:
            self._http = httpx.AsyncClient(
                headers=_HEADERS,
                follow_redirects=True,
                timeout=30,
            )
        return self._http

    # ── Free public numbers ──────────────────────────────────────────

    @tool_method(name="list_free_phone_numbers", catch=True)
    async def list_free_phone_numbers(
        self,
        country: Annotated[
            str,
            "Filter by country name (e.g. 'United States', 'United Kingdom'). "
            "Use 'all' for every available number.",
        ] = "all",
    ) -> str:
        """List available free public phone numbers from receive-smss.com.

        Returns numbers the agent can immediately use for verification flows.
        These are shared public numbers — anyone can see messages. Use for
        signup, MFA testing, and account recovery where privacy is not needed.
        If the target blocks public numbers, fall back to request_private_number.
        """
        client = await self._client()
        try:
            resp = await client.get("https://receive-smss.com/")
            resp.raise_for_status()
        except Exception as exc:
            return f"Error: Failed to fetch numbers: {exc}"

        numbers = _parse_numbers_from_html(resp.text)
        if not numbers:
            return "Error: No numbers found. Site structure may have changed."

        if country.lower() != "all":
            needle = country.lower()
            numbers = [n for n in numbers if needle in n["country"].lower()]

        if not numbers:
            return f"No numbers found for country '{country}'. Try 'all' to see available countries."

        lines = [f"Found {len(numbers)} number(s):"]
        for n in numbers:
            lines.append(f"  {n['number']:<20} {n['country']:<20} {n['inbox_url']}")

        lines.append(
            "\nUse read_phone_inbox with the number to check for verification codes."
        )
        return "\n".join(lines)

    @tool_method(name="read_phone_inbox", catch=True)
    async def read_phone_inbox(
        self,
        phone_number: Annotated[
            str,
            "Phone number (digits only or with +). "
            "Or a full inbox URL from a free SMS provider.",
        ],
        sender_filter: Annotated[
            str,
            "Only show messages from this sender (substring match). "
            "Empty string for all messages.",
        ] = "",
        code_regex: Annotated[
            str,
            "Regex to extract verification codes. Default: 4-8 digit codes.",
        ] = _DEFAULT_CODE_REGEX,
    ) -> str:
        """Read a public phone inbox and extract verification codes.

        Works with receive-smss.com numbers (from list_free_phone_numbers)
        or any direct inbox URL. Parses messages and extracts OTP codes.
        """
        # Determine URL
        if phone_number.startswith("http"):
            url = phone_number
        else:
            digits = re.sub(r"[^\d]", "", phone_number)
            url = f"https://receive-smss.com/sms/{digits}/"

        client = await self._client()
        try:
            resp = await client.get(url)
            resp.raise_for_status()
        except Exception as exc:
            return f"Error: Failed to fetch inbox: {exc}"

        messages = _parse_messages_from_html(resp.text)

        if sender_filter:
            needle = sender_filter.lower()
            messages = [m for m in messages if needle in m["sender"].lower()]

        # Extract codes from all message bodies
        all_text = " ".join(m["body"] for m in messages)
        codes = _extract_codes(all_text, code_regex)

        if not messages:
            # Fallback: try generic HTML text extraction
            text = _html_to_text(resp.text)
            codes = _extract_codes(text, code_regex)
            return json.dumps(
                {
                    "messages": [],
                    "codes": codes,
                    "note": "No structured messages found. Codes extracted from raw page.",
                    "preview": text[:500],
                },
                indent=2,
            )

        return json.dumps(
            {
                "messages": messages[:10],
                "codes": codes,
            },
            indent=2,
        )

    # ── Paid private numbers (SMS-Activate compatible API) ───────────

    @tool_method(name="request_private_number", catch=True)
    async def request_private_number(
        self,
        api_url: Annotated[
            str,
            "SMS-Activate compatible API endpoint. Common providers: "
            "sms-man.com, 5sim.net, sms-activate.org, smshub.org. "
            "Example: https://api.sms-man.com/stubs/handler_api.php",
        ],
        api_key: Annotated[str, "Provider API key (use get_credential to retrieve)."],
        service: Annotated[str, "Service code: tg=Telegram, go=Google, wa=WhatsApp, ds=Discord, etc."],
        country: Annotated[str, "Country code (provider-specific). Use '0' for default."] = "0",
    ) -> str:
        """Request a private phone number from a paid SMS activation API.

        Use when free public numbers are blocked by the target application.
        The SMS-Activate protocol is shared by sms-man, 5sim, sms-activate,
        smshub, and other providers — same request format, different base URLs.
        Returns a request_id and phone_number. Use poll_private_number to get the code.
        """
        client = await self._client()
        try:
            resp = await client.get(
                api_url,
                params={
                    "api_key": api_key,
                    "action": "getNumber",
                    "service": service,
                    "country": country,
                },
            )
            resp.raise_for_status()
            result = resp.text.strip()
        except Exception as exc:
            return f"Error: API request failed: {exc}"

        if not result.startswith("ACCESS_NUMBER:"):
            return f"Provider response: {result}"

        parts = result.split(":", 2)
        if len(parts) < 3:
            return f"Error: Unexpected format: {result}"

        return json.dumps(
            {"request_id": parts[1], "phone_number": parts[2]},
            indent=2,
        )

    @tool_method(name="poll_private_number", catch=True)
    async def poll_private_number(
        self,
        api_url: Annotated[str, "Same API endpoint used in request_private_number."],
        api_key: Annotated[str, "Provider API key."],
        request_id: Annotated[str, "Activation ID from request_private_number."],
        code_regex: Annotated[
            str,
            "Regex to extract codes from the SMS body. Default: 4-8 digit codes.",
        ] = _DEFAULT_CODE_REGEX,
    ) -> str:
        """Poll a paid SMS activation API for the verification code.

        Call after the target application sends the SMS. May need multiple
        calls — the provider returns STATUS_WAIT_CODE until the SMS arrives.
        """
        client = await self._client()
        try:
            resp = await client.get(
                api_url,
                params={
                    "api_key": api_key,
                    "action": "getStatus",
                    "id": request_id,
                },
            )
            resp.raise_for_status()
            result = resp.text.strip()
        except Exception as exc:
            return f"Error: API request failed: {exc}"

        if result.startswith("STATUS_WAIT_CODE"):
            return "Waiting for SMS. Try again in 10-15 seconds."

        if not result.startswith("STATUS_OK:"):
            return f"Provider response: {result}"

        message = result.split(":", 1)[1]
        codes = _extract_codes(message, code_regex)
        return json.dumps(
            {"request_id": request_id, "message": message, "codes": codes},
            indent=2,
        )
