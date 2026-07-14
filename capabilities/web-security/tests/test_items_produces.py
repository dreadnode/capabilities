"""Regression tests for structured ``produces`` item schemas (CAP-1152).

The web-security manifest declares custom structured output types via
``produces`` (``web_vulnerability`` / ``web_endpoint``) plus the built-in
``finding`` / ``asset`` types. The Dreadnode capability loader and the OCI
packager import ``items.py`` by path **without** registering it in
``sys.modules`` and then call ``model_json_schema()``. Because ``items.py``
uses ``from __future__ import annotations`` (PEP 563), Pydantic must resolve
forward references lazily — which fails in that unregistered-module state
unless the models are rebuilt at import time.

These tests reproduce the loader's exact import path and assert that every
declared model produces a JSON schema, guaranteeing the typed ``report_item``
tool (and the published package schemas) build cleanly.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel

ITEMS_PATH = (Path(__file__).resolve().parent.parent / "items.py").resolve()

# Types the manifest's `produces:` block references by "module:Class".
PRODUCED_MODELS = ("WebVulnerability", "WebEndpoint")


def _load_items_like_the_loader():
    """Import items.py exactly the way the SDK loader/packager does.

    ``spec_from_file_location`` + ``module_from_spec`` + ``exec_module`` with
    NO ``sys.modules`` registration and a unique module name — the precise
    conditions under which the forward-reference bug manifests.
    """
    mod_name = "_dn_test_web_security_items_cap1152"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(mod_name, ITEMS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Intentionally NOT added to sys.modules — matches report_items.py and oci.py.
    spec.loader.exec_module(module)
    return module


def test_items_file_exists():
    assert ITEMS_PATH.is_file(), f"items.py not found at {ITEMS_PATH}"


@pytest.mark.parametrize("class_name", PRODUCED_MODELS)
def test_produced_model_schema_builds_under_loader_import(class_name):
    """Each `produces`-referenced model must yield a JSON schema when imported
    the way the loader does. This is the exact call that previously raised
    ``PydanticUserError: ... is not fully defined``."""
    module = _load_items_like_the_loader()
    model = getattr(module, class_name)
    schema = model.model_json_schema()
    assert schema["type"] == "object"
    assert "properties" in schema


def test_all_module_models_are_fully_defined():
    """Scalable guard: every BaseModel subclass defined in items.py must build
    a schema — so newly added types can never silently regress."""
    module = _load_items_like_the_loader()
    models = [
        obj
        for obj in vars(module).values()
        if isinstance(obj, type)
        and issubclass(obj, BaseModel)
        and obj is not BaseModel
        and obj.__module__ == module.__name__
    ]
    assert models, "expected at least one BaseModel defined in items.py"
    for model in models:
        schema = model.model_json_schema()  # must not raise
        assert schema["type"] == "object"


def test_severity_forward_reference_resolves():
    """WebVulnerability.severity uses the module-level ``Severity`` literal — the
    forward reference that triggered the original failure. Confirm it resolved
    to the expected enum values in the built schema."""
    module = _load_items_like_the_loader()
    schema = module.WebVulnerability.model_json_schema()
    # `severity` is required and enumerates the Severity literal values.
    props = schema["properties"]
    assert "severity" in props
    flat = str(props["severity"])
    for value in ("critical", "high", "medium", "low", "informational"):
        assert value in flat


def test_nested_cvss_models_resolve():
    """Nested optional CVSS models must also resolve under the loader import."""
    module = _load_items_like_the_loader()
    schema = module.WebVulnerability.model_json_schema()
    # $defs should include the nested CVSS model schemas.
    defs = schema.get("$defs", {})
    assert "CvssV31" in defs
    assert "CvssV40" in defs
