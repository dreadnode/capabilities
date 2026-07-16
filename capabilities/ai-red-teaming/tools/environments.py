"""Deployable agent environments for multi-agent red teaming.

Tools that let the AI red-teaming agent provision a hosted **task environment**
(e.g. the ``finops-mesh`` / ``devsecops-mesh`` / ``healthcare-mesh`` /
``soc-mesh`` multi-agent systems) and target it with ATLAS — closing the loop
between the Environments the platform hosts and ``generate_atlas_attack``.

Provisioning uses the SDK's ``TaskEnvironment`` (platform Docker/E2B sandbox
provider). The model the environment's agents use is passed in via
``model_overrides`` (the platform task-environment model capability) so the
deployed agents run the model you choose.
"""

from __future__ import annotations

import asyncio
import importlib.util as _ilu
import typing as t
from pathlib import Path as _Path

# Load the shared safe_tool wrapper by file path (flat-module loading).
_errors_path = _Path(__file__).resolve().parent / "errors.py"
_spec = _ilu.spec_from_file_location("airt_tools_errors", _errors_path)
_errors_mod = _ilu.module_from_spec(_spec)
_spec.loader.exec_module(_errors_mod)
safe_tool = _errors_mod.safe_tool


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


@safe_tool
def provision_environment(
    task_ref: t.Annotated[str, "Environment/task to deploy, e.g. 'finops-mesh'"],
    model: t.Annotated[
        str, "Model the environment's agents use (e.g. 'dn/claude-haiku-4-5', 'groq/llama-3.3-70b-versatile')"
    ] = "",
    model_role: t.Annotated[str, "Role key to override with the model (default 'agent')"] = "agent",
    timeout_sec: t.Annotated[int, "Provision + run budget in seconds"] = 1800,
) -> str:
    """Provision a hosted multi-agent environment and return its attack URL.

    Deploys the environment via the platform sandbox provider, passing ``model``
    to the environment's agents (task-environment model capability). Returns the
    ``/attack`` base URL and the bearer execute token — pass the URL to
    ``generate_atlas_attack`` (``agent_url=<url>/attack``) with
    ``agent_auth_type='bearer'`` and the token via the ``AGENT_API_KEY`` env.
    """
    from dreadnode.core.environment import TaskEnvironment

    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return "Not configured for a platform org/workspace. Run `dreadnode login` first."

    model_overrides = {model_role: model} if model else None
    env = TaskEnvironment(
        api, org=org, workspace=workspace, task_ref=task_ref,
        model_overrides=model_overrides, timeout_sec=timeout_sec,
    )
    ctx = _run(env.setup())
    svc = (ctx.get("service_urls") or {}).get("challenge")
    url = (svc.get("url") if isinstance(svc, dict) else svc) or ""
    token = env._execute_token or ""  # noqa: SLF001 - one-shot provision token
    if not url:
        return f"Environment '{task_ref}' provisioned but exposed no 'challenge' URL: {ctx.get('service_urls')}"

    return (
        f"Environment '{task_ref}' is ready.\n"
        f"  Attack URL: {url}/attack\n"
        f"  Auth: bearer (execute token below)\n"
        f"  Execute token: {token}\n"
        f"  Model: {model or '(env default)'}\n\n"
        f">>> NEXT STEP: run ATLAS against it — call generate_atlas_attack("
        f"agent_url=\"{url}/attack\", agent_auth_type=\"bearer\", "
        f"scenario_name=\"{task_ref.replace('-mesh', '')}\", attacker_model=\"groq scout\") "
        f"and set AGENT_API_KEY to the execute token above."
    )
