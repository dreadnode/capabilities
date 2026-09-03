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


# Dreadnode-hosted traditional-ML /predict classifiers, provisionable for
# evasion / extraction / membership / inversion attacks.
_ML_TARGETS: dict[str, dict] = {
    "ml-extraction-fraud-tabular": {
        "modality": "tabular", "num_classes": 2, "input_dim": 30,
        "label": "Credit-card fraud (tabular)",
    },
    "ml-extraction-mnist-image": {
        "modality": "image", "num_classes": 10, "input_shape": [8, 8],
        "label": "Handwritten digits (image)",
    },
    "ml-extraction-imdb-text": {
        "modality": "text", "num_classes": 2,
        "label": "Movie-review sentiment (text)",
    },
}


def _fetch_seed(members_url: str) -> t.Any:
    """Fetch one sample record from a hosted target's /members endpoint (best effort)."""
    import json as _json
    import urllib.request as _u

    try:
        with _u.urlopen(members_url, timeout=30) as r:  # noqa: S310 - platform sandbox URL
            data = _json.loads(r.read().decode())
        recs = data.get("records") or data.get("inputs") or []
        return recs[0] if recs else None
    except Exception:
        return None


@safe_tool
def list_ml_targets() -> str:
    """List Dreadnode-hosted traditional-ML classifier targets (fraud/tabular,
    MNIST/image, IMDB/text) you can deploy with ``provision_ml_target``.

    For your own classifier, skip provisioning and pass its predict URL directly
    to generate_evasion_attack / generate_extraction_attack /
    generate_membership_attack / generate_inversion_attack via ``api_url``.
    """
    lines = ["Hosted traditional-ML targets (deploy with provision_ml_target):"]
    for ref, spec in _ML_TARGETS.items():
        shape = spec.get("input_shape") or spec.get("input_dim")
        lines.append(
            f"  - {ref}  [{spec['modality']}, {spec['num_classes']} classes"
            f"{f', shape/dim={shape}' if shape else ''}]  {spec['label']}"
        )
    lines.append("\nOwn target? Pass its /predict URL to any trad-ML attack tool via api_url.")
    return "\n".join(lines)


@safe_tool
def provision_ml_target(
    task_ref: t.Annotated[
        str, "Hosted ML target to deploy (e.g. 'ml-extraction-fraud-tabular'); see list_ml_targets."
    ],
    timeout_sec: t.Annotated[int, "Provision budget in seconds"] = 600,
) -> str:
    """Deploy a Dreadnode-hosted traditional-ML classifier and return its /predict URL
    plus a seed input, ready to hand to the evasion / extraction / membership / inversion tools.

    Use this when the user wants to attack a **Dreadnode** target. For the user's **own**
    classifier, skip this and pass their predict URL directly via ``api_url``.
    """
    from dreadnode.core.environment import TaskEnvironment

    _inst, api, org, workspace = _configured()
    if not org or not workspace:
        return "Not configured for a platform org/workspace. Run `dreadnode login` first."

    env = TaskEnvironment(api, org=org, workspace=workspace, task_ref=task_ref, timeout_sec=timeout_sec)
    ctx = _run(env.setup())
    svc = (ctx.get("service_urls") or {}).get("challenge")
    url = (svc.get("url") if isinstance(svc, dict) else svc) or ""
    if not url:
        return f"Target '{task_ref}' provisioned but exposed no 'challenge' URL: {ctx.get('service_urls')}"

    predict_url = f"{url}/predict"
    pool_url = f"{url}/pool?n=50"
    members_url = f"{url}/members?n=1"
    members_pool_url = f"{url}/members?n=200"
    nonmembers_url = f"{url}/nonmembers?n=200"
    spec = _ML_TARGETS.get(task_ref, {})
    modality = spec.get("modality", "tabular")
    num_classes = spec.get("num_classes")
    seed = _fetch_seed(members_url)

    lines = [
        f"Target '{task_ref}' is ready.",
        f"  Predict URL: {predict_url}",
        f"  Pool URL:    {pool_url}   (query inputs for extraction; derives input_dim)",
        f"  Members URL: {members_url}   (labeled records for membership/evasion seeds)",
        f"  Modality:    {modality}",
    ]
    if num_classes is not None:
        lines.append(f"  Classes:     {num_classes}")
    if spec.get("input_shape"):
        lines.append(f"  Input shape: {spec['input_shape']} (for inversion)")
    if spec.get("input_dim"):
        lines.append(f"  Input dim:   {spec['input_dim']} (for inversion)")
    if seed is not None:
        preview = repr(seed)
        lines.append(f"  Seed input:  {preview[:160]}{'...' if len(preview) > 160 else ''}")

    nc = num_classes if num_classes is not None else 2
    lines += [
        "",
        ">>> NEXT STEP: run an attack against it, e.g.:",
        f'  - Evasion:    generate_evasion_attack(api_url="{predict_url}", modality="{modality}", '
        f'num_classes={nc}, original=<the seed input above or a record from {members_url}>)',
        f'  - Extraction: generate_extraction_attack(api_url="{predict_url}", pool_url="{pool_url}", '
        f'num_classes={nc}, modality="{modality}")',
        f'  - Membership: generate_membership_attack(api_url="{predict_url}", num_classes={nc}, '
        f'modality="{modality}", members_url="{members_pool_url}", nonmembers_url="{nonmembers_url}")',
        f'  - Inversion:  generate_inversion_attack(api_url="{predict_url}", num_classes={nc}, '
        f'modality="{modality}", '
        + (f'input_shape={spec.get("input_shape")}' if spec.get("input_shape") else f'pool_url="{pool_url}"')
        + ")",
    ]
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
