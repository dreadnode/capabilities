"""Deployable agent environments for multi-agent red teaming.

Tools that let the AI red-teaming agent provision a hosted **task environment**
(e.g. the ``finops-mesh`` / ``devsecops-mesh`` / ``healthcare-mesh`` /
``soc-mesh`` tool-misuse pipelines, ``devops-rce-mesh`` for real code execution,
and ``support-exfil-mesh`` for data exfiltration) and target it with ATLAS —
closing the loop between the Environments the platform hosts and
``generate_atlas_attack``.

Provisioning uses the SDK's ``TaskEnvironment`` (platform Docker/E2B sandbox
provider). The model the environment's agents use is passed in via
``model_overrides`` (the platform task-environment model capability) so the
deployed agents run the model you choose.
"""

from __future__ import annotations

import asyncio
import importlib.util as _ilu
import json as _json
import os as _os
import time as _time
import typing as t
from datetime import datetime, timezone
from pathlib import Path as _Path

# Load the shared safe_tool wrapper by file path (flat-module loading).
_errors_path = _Path(__file__).resolve().parent / "errors.py"
_spec = _ilu.spec_from_file_location("airt_tools_errors", _errors_path)
_errors_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_errors_mod)
safe_tool = _errors_mod.safe_tool

# Session registry of provisioned environments. Hosted sandboxes bill for their
# whole lifetime, so every provision is recorded here and torn down when the
# assessment completes (see tools/assessment.py) or via teardown_environment.
# File-based so it survives across separate tool invocations in one session;
# path is overridable for tests.
REGISTRY_PATH = _Path(_os.environ.get("AIRT_ENV_REGISTRY_PATH", "/tmp/airt_environments.json"))


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _registry_load(registry_path: _Path = REGISTRY_PATH) -> list[dict]:
    """Return the provisioned-environment records, tolerating a missing/corrupt file."""
    try:
        if registry_path.exists():
            data = _json.loads(registry_path.read_text())
            if isinstance(data, list):
                return [e for e in data if isinstance(e, dict)]
    except (OSError, ValueError):
        pass
    return []


def _registry_save(entries: list[dict], registry_path: _Path = REGISTRY_PATH) -> None:
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(_json.dumps(entries, indent=2))


def _registry_add(entry: dict, registry_path: _Path = REGISTRY_PATH) -> None:
    entries = [e for e in _registry_load(registry_path) if e.get("id") != entry.get("id")]
    entries.append(entry)
    _registry_save(entries, registry_path)


def _registry_remove(env_id: str, registry_path: _Path = REGISTRY_PATH) -> None:
    _registry_save(
        [e for e in _registry_load(registry_path) if e.get("id") != env_id], registry_path
    )


def _register_provisioned(
    env: t.Any, task_ref: str, org: str, workspace: str, registry_path: _Path = REGISTRY_PATH
) -> str:
    """Record a just-provisioned environment in the session registry. Returns its id
    (empty string if the environment exposed none, e.g. a provision that never became
    ready)."""
    env_id = getattr(env, "id", None) or ""
    if not env_id:
        return ""
    _registry_add(
        {
            "id": env_id,
            "task_ref": task_ref,
            "org": org,
            "workspace": workspace,
            "provisioned_at": _iso_now(),
            "provisioned_at_ts": _time.time(),
        },
        registry_path,
    )
    return env_id


def _entry_age(entry: dict, now: float) -> float | None:
    ts = entry.get("provisioned_at_ts")
    if isinstance(ts, (int, float)):
        return max(0.0, now - float(ts))
    return None


def _is_not_found(exc: BaseException) -> bool:
    """A delete of an already-gone environment is success, not failure."""
    try:
        from dreadnode.app.api.client import NotFoundError

        if isinstance(exc, NotFoundError):
            return True
    except Exception:  # noqa: BLE001 - NotFoundError may be absent on older SDKs
        pass
    return "notfound" in exc.__class__.__name__.lower() or "404" in str(exc)


def _teardown_environments(
    api: t.Any,
    org: str,
    workspace: str,
    *,
    environment_id: str = "",
    older_than_sec: float = 0.0,
    registry_path: _Path = REGISTRY_PATH,
    now_ts: float | None = None,
) -> dict:
    """Delete provisioned environments and prune the registry.

    Pure and testable: the API client is injected. Idempotent - deleting an
    already-gone environment counts as torn down. ``older_than_sec`` is a grace
    window: an environment provisioned more recently than that is left alone so
    an in-flight attack is not killed out from under it.

    Returns ``{"torn_down": [ids], "skipped": [ids], "errors": {id: msg}}``.
    """
    now = _time.time() if now_ts is None else now_ts
    entries = _registry_load(registry_path)
    if environment_id:
        targets = [e for e in entries if e.get("id") == environment_id] or [
            {"id": environment_id}
        ]
    else:
        targets = list(entries)

    torn: list[str] = []
    skipped: list[str] = []
    errors: dict[str, str] = {}
    for entry in targets:
        env_id = entry.get("id")
        if not env_id:
            continue
        age = _entry_age(entry, now)
        if older_than_sec > 0 and age is not None and age < older_than_sec:
            skipped.append(env_id)
            continue
        try:
            api.delete_environment(org, workspace, env_id)
            torn.append(env_id)
            _registry_remove(env_id, registry_path)
        except Exception as exc:  # noqa: BLE001 - tolerate already-gone / provider errors
            if _is_not_found(exc):
                torn.append(env_id)
                _registry_remove(env_id, registry_path)
            else:
                errors[env_id] = str(exc)
    return {"torn_down": torn, "skipped": skipped, "errors": errors}


def teardown_session_environments(
    older_than_sec: float = 0.0, registry_path: _Path = REGISTRY_PATH
) -> dict:
    """Reap every environment in the session registry. Used by the assessment
    completion hook. Short-circuits (no platform call) when nothing is registered.

    Deliberately NOT a tool (no @safe_tool): this is a shared helper, invoked
    directly by assessment.py's completion teardown and by tests. Adding @tool
    would expose a user-callable teardown that bypasses assessment lifecycle.
    """
    if not _registry_load(registry_path):
        return {"torn_down": [], "skipped": [], "errors": {}}
    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return {"torn_down": [], "skipped": [], "errors": {}}
    return _teardown_environments(
        api, org, workspace, older_than_sec=older_than_sec, registry_path=registry_path
    )


def _run(coro: t.Any) -> t.Any:
    """Run an async coroutine from a sync tool, whether or not a loop is running."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # A loop is already running (e.g. inside the runtime) — run on a fresh loop
    # in a worker thread so we don't reenter the active loop.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(coro)).result()


def _configured():
    """Return (instance, ApiClient, org, workspace) from the resolved SDK config."""
    import dreadnode as dn

    inst = dn.configure()
    api = inst.api
    org = str(inst.organization) if inst.organization else None
    workspace = str(inst.workspace) if inst.workspace else None
    if not org:
        orgs = api.list_user_organizations()
        org = orgs[0].key if orgs else None
    return inst, api, org, workspace


@safe_tool
def list_environments() -> str:
    """List deployable multi-agent environments (hosted task environments).

    These are the systems ATLAS can be pointed at — provision one with
    ``provision_environment`` to get its attack URL.
    """
    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return "Not configured for a platform org/workspace. Run `dreadnode login` first."
    data = api.list_environments(org, workspace, limit=50)
    envs = data.get("environments") or data.get("items") or []
    if not envs:
        # Fall back to the task registry — tasks are the provisionable environments.
        tasks = api.list_tasks(org) if hasattr(api, "list_tasks") else {}
        names = [t_.get("name") for t_ in (tasks.get("tasks") or tasks.get("items") or [])]
        multiagent = [n for n in names if n and n.endswith("-mesh")]
        listing = ", ".join(multiagent or names[:20]) or "(none)"
        return f"Provisionable environments (task refs): {listing}"
    lines = ["Environments:"]
    for e in envs:
        lines.append(f"  - {e.get('task_ref')} [{e.get('state')}] id={e.get('id')}")
    return "\n".join(lines)


def _target_kind(task_ref: str) -> str:
    """Classify a provisionable target so we return the right endpoint + guidance.

    - 'classifier': black-box ML target that serves /predict (+ /pool, /members,
      /nonmembers) - evasion / extraction / membership / inversion.
    - 'mesh': multi-agent environment that serves /attack - ATLAS.
    - 'unknown': fall back to a non-prescriptive message.
    """
    ref = (task_ref or "").lower()
    if ref.endswith("-mesh") or "mesh" in ref:
        return "mesh"
    if ("ml-extraction" in ref or "classifier" in ref or "extraction" in ref
            or any(k in ref for k in ("mnist", "fraud", "imdb", "tabular", "image", "text"))):
        return "classifier"
    return "unknown"


@safe_tool
def provision_environment(
    task_ref: t.Annotated[str, "Environment/task to deploy, e.g. 'finops-mesh' or 'ml-extraction-mnist-image'"],
    model: t.Annotated[
        str, "Model the environment's agents use (e.g. 'dn/claude-haiku-4-5', 'groq/llama-3.3-70b-versatile')"
    ] = "",
    model_role: t.Annotated[str, "Role key to override with the model (default 'agent')"] = "agent",
    timeout_sec: t.Annotated[int, "Provision + run budget in seconds"] = 1800,
) -> str:
    """Provision a hosted target environment and return the correct endpoint for it.

    Deploys the environment via the platform sandbox provider. The next step
    depends on the target type:
    - a black-box ML classifier (e.g. ``ml-extraction-mnist-image``) serves
      ``/predict`` - use ``generate_evasion_attack`` / ``generate_extraction_attack``
      / ``generate_membership_attack`` / ``generate_inversion_attack``.
    - a multi-agent mesh (e.g. ``finops-mesh``) serves ``/attack`` - use
      ``generate_atlas_attack``.
    Do not probe ``/attack`` on a classifier target; it does not serve it.
    """
    from dreadnode.core.environment import TaskEnvironment
    # NOTE: tests/test_tool_surface.py (TestProvisionErrorContract) monkeypatches
    # `dreadnode.core.environment.TaskEnvironment` and relies on this lazy import
    # to take effect. If this import is ever hoisted to module level, update those
    # tests to patch the module-level binding instead.

    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return "Not configured for a platform org/workspace. Run `dreadnode login` first."

    model_overrides = {model_role: model} if model else None

    def _mk(ref: str) -> t.Any:
        return TaskEnvironment(
            api, org=org, workspace=workspace, task_ref=ref,
            model_overrides=model_overrides, timeout_sec=timeout_sec,
        )

    # A bare name resolves to a task in the caller's org or any public task
    # (server-side visibility rule), so bundled public targets work by bare name.
    # A task owned by another org resolves only when it is public or owned by the
    # caller - a private cross-org task 404s the same way whether or not it is
    # qualified, so there is no client-side retry that helps; just add a hint.
    env = _mk(task_ref)
    try:
        ctx = _run(env.setup())
    except Exception as exc:  # noqa: BLE001 - add a resolution hint on not-found
        if not _is_not_found(exc):
            raise
        # A user-input error, not an internal fault: return a plain "Error:"
        # string (per the skill contract, "Error:" = adjust params, don't
        # blind-retry) instead of raising, so safe_tool does not mislabel it
        # as an internal tool issue.
        return (
            f"Error: Task '{task_ref}' not found. A bare name resolves to a task "
            "in your org or any public task, so a not-found here means the task is "
            "private to another org (no <org>/<name> qualification can bypass that "
            "visibility rule) or the name/version is wrong - check the name and "
            "version."
        )
    svc = (ctx.get("service_urls") or {}).get("challenge")
    url = (svc.get("url") if isinstance(svc, dict) else svc) or ""
    token = env._execute_token or ""  # noqa: SLF001 - one-shot provision token
    # Record the sandbox so it is torn down at assessment completion even if the
    # attack path forgets - a hosted sandbox bills for its whole lifetime.
    env_id = _register_provisioned(env, task_ref, org, workspace)
    if not url:
        return f"Environment '{task_ref}' provisioned but exposed no 'challenge' URL: {ctx.get('service_urls')}"

    url = url.rstrip("/")
    kind = _target_kind(task_ref)
    header = (
        f"Environment '{task_ref}' is ready.\n"
        f"  Environment id: {env_id}\n"
        f"  Base URL: {url}\n"
        f"  Model: {model or '(env default)'}\n"
    )
    teardown_note = (
        "\n>>> WHEN DONE: this sandbox bills for its whole lifetime - it is torn down "
        "automatically once every planned attack is recorded (pass or fail). If you abandon "
        "the run without recording all attacks, call teardown_environment() now so it does not "
        "bill until its TTL. For long runs set AIRT_ENV_TEARDOWN_GRACE_SEC >= your longest "
        "attack timeout so completion-teardown does not kill an in-flight attack."
    )

    if kind == "classifier":
        return (
            header
            + f"  Predict endpoint: {url}/predict   (dataset helpers: {url}/pool, /members, /nonmembers)\n\n"
            + ">>> NEXT STEP: this is a black-box ML classifier. Do NOT fetch /attack - it does not "
              "serve it. Run the matching attack with the predict endpoint, e.g.:\n"
            + f'    generate_evasion_attack(attack_type="hopskipjump", api_url="{url}/predict", ...)\n'
            + "    (or generate_extraction_attack / generate_membership_attack / generate_inversion_attack)\n"
            + "    These tools query /predict and pull data from /pool, /members, /nonmembers automatically."
            + teardown_note
        )
    if kind == "mesh":
        return (
            header
            + f"  Attack URL: {url}/attack\n"
            + f"  Auth: bearer (execute token below)\n"
            + f"  Execute token: {token}\n\n"
            + ">>> NEXT STEP: run ATLAS against it - call generate_atlas_attack("
            + f'agent_url="{url}/attack", agent_auth_type="bearer", '
            + f'scenario_name="{task_ref.replace("-mesh", "")}", attacker_model="groq scout") '
            + "and set AGENT_API_KEY to the execute token above."
            + teardown_note
        )
    # unknown: describe both without prescribing a wrong endpoint
    return (
        header
        + f"  Execute token: {token}\n\n"
        + ">>> NEXT STEP: inspect the target before attacking. A black-box ML classifier "
          f"serves {url}/predict (use generate_evasion_attack / extraction / membership / "
          f"inversion); a multi-agent mesh serves {url}/attack (use generate_atlas_attack). "
          "Do not assume /attack exists."
        + teardown_note
    )


@safe_tool
def teardown_environment(
    environment_id: t.Annotated[
        str,
        "Environment id to tear down. Leave empty to tear down EVERY environment "
        "provisioned in this session.",
    ] = "",
    older_than_sec: t.Annotated[
        int,
        "Only tear down environments provisioned at least this many seconds ago "
        "(0 = no age filter). Guards a still-running attack from being killed.",
    ] = 0,
) -> str:
    """Tear down (delete) provisioned environment sandboxes to stop billing.

    Call this once your attacks are done. Hosted sandboxes bill for their whole
    lifetime, so leaving them running costs credits. With no ``environment_id``
    this reaps every environment provisioned in the current session; pass an id
    to reap just one. Idempotent - an environment already gone counts as torn
    down.
    """
    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return "Not configured for a platform org/workspace. Run `dreadnode login` first."
    result = _teardown_environments(
        api,
        org,
        workspace,
        environment_id=environment_id,
        older_than_sec=float(older_than_sec),
    )
    parts = [f"Tore down {len(result['torn_down'])} environment(s)."]
    if result["skipped"]:
        parts.append(f"Skipped {len(result['skipped'])} within the grace window.")
    if result["errors"]:
        parts.append(
            "Errors: " + "; ".join(f"{k}: {v}" for k, v in result["errors"].items())
        )
    return " ".join(parts)
