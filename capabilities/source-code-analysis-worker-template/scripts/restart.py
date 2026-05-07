"""Restart a Dreadnode runtime sandbox to pick up freshly-pushed capability code.

Capability code is bundled into the sandbox image at provision time, so a
new version of a capability only reaches a runtime after the sandbox is
reset and re-started. This script wraps that two-step bounce::

    api.reset_runtime(...)
    api.start_runtime(...)

…and optionally a config update if you want to bump the capability version
on the runtime spec at the same time.

Auth: this hits the *platform* API (not the sandbox URL) and uses your
platform API key — the same one ``dn login`` writes to your profile. The
script picks it up via ``create_api_client()`` so no explicit token is
required.

Typical use, after you ``dn capability push --force`` the capability::

    uv run --project packages/sdk python scripts/restart.py \\
        3b88fd4e-3ea0-40b9-a2b2-b2cf5c6def83 \\
        --org dreadnode --workspace main

Prints the new ``sandbox_url`` and ``sandbox_token`` so you can paste them
into the launcher.
"""

import argparse
import os
import sys
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", maxsplit=1)[0])
    parser.add_argument("runtime_id", help="Runtime UUID")
    parser.add_argument(
        "--org",
        default=os.environ.get("DREADNODE_ORG"),
        help="Organization slug (default: $DREADNODE_ORG).",
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("DREADNODE_WORKSPACE"),
        help="Workspace slug (default: $DREADNODE_WORKSPACE).",
    )
    parser.add_argument(
        "--bump-version",
        default=None,
        metavar="VERSION",
        help=(
            "Optional new version for a capability on the runtime spec. "
            "Requires --capability. Updates runtime config before the bounce."
        ),
    )
    parser.add_argument(
        "--capability",
        default=None,
        metavar="NAME",
        help=(
            "Capability name to bump (e.g. dreadnode/source-code-analysis-worker-template). "
            "Required when --bump-version is set."
        ),
    )
    args = parser.parse_args()
    if not args.org:
        parser.error("--org or $DREADNODE_ORG is required")
    if not args.workspace:
        parser.error("--workspace or $DREADNODE_WORKSPACE is required")
    if (args.bump_version is not None) ^ (args.capability is not None):
        parser.error("--bump-version and --capability must be used together")
    return args


def update_capability_version(
    api: Any, org: str, workspace: str, runtime_id: str, capability: str, version: str
) -> None:
    """Bump one capability's version on the runtime config in place."""
    current = api.get_runtime_config(org, workspace, runtime_id).get("config", {})
    matched = False
    for cap in current.get("capabilities", []):
        if cap.get("name") == capability:
            cap["version"] = version
            matched = True
    if not matched:
        raise SystemExit(
            f"Capability {capability!r} not found on runtime {runtime_id}; "
            "check the spelling against `dn runtime get`."
        )
    api.update_runtime_config(org, workspace, runtime_id, current)
    print(f"Bumped {capability} → {version}")


def print_sandbox_info(payload: Any) -> None:
    """Pull the bits an operator needs from the start_runtime response."""
    instance = payload.get("instance") if isinstance(payload, dict) else None
    if not isinstance(instance, dict):
        # Older response shape; just dump the lot.
        import json

        print(json.dumps(payload, indent=2, default=str))
        return

    print()
    print("Sandbox started.")
    print(f"  sandbox_url:   {instance.get('sandbox_url') or '(missing)'}")
    print(f"  sandbox_token: {payload.get('sandbox_token') or '(missing)'}")
    print(f"  expires_at:    {instance.get('expires_at') or '(unknown)'}")
    print(f"  state:         {instance.get('state') or '(unknown)'}")


def main() -> int:
    args = parse_args()

    # Imported here so --help works without the SDK installed.
    from dreadnode.app.api.client import create_api_client

    api = create_api_client()

    if args.bump_version is not None:
        update_capability_version(
            api,
            args.org,
            args.workspace,
            args.runtime_id,
            args.capability,
            args.bump_version,
        )

    print(f"Resetting runtime {args.runtime_id}...")
    api.reset_runtime(args.org, args.workspace, args.runtime_id)

    print("Starting runtime...")
    started = api.start_runtime(args.org, args.workspace, args.runtime_id)

    print_sandbox_info(started)
    return 0


if __name__ == "__main__":
    sys.exit(main())
