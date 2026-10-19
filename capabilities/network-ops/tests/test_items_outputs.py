"""Regression tests for the network-ops structured ``outputs`` item schemas.

The manifest declares AD record types via ``outputs:`` (``host``, ``user``,
``credential``, ``hash``, ``share``, ``weakness``) whose models live in
``items.py``, plus the built-in ``finding`` / ``asset`` types. The Dreadnode
capability loader and OCI packager import ``items.py`` by path **without**
registering it in ``sys.modules`` and then call ``model_json_schema()``.

These tests reproduce that import path and lock in two guarantees: fields an
operator cannot know are optional (so realistic findings validate instead of
failing or being hallucinated), and host role is an explicit discriminator
rather than inferred from which optional fields happen to be populated.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

ITEMS_PATH = (Path(__file__).resolve().parent.parent / "items.py").resolve()

# Types the manifest's `outputs:` block references by "module:Class".
DECLARED_MODELS = ("Host", "User", "Credential", "Hash", "Share", "Weakness")


def _load_items_like_the_loader():
    """Import items.py exactly the way the SDK loader/packager does."""
    mod_name = "_dn_test_network_ops_items"
    sys.modules.pop(mod_name, None)
    spec = importlib.util.spec_from_file_location(mod_name, ITEMS_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Intentionally NOT added to sys.modules — matches report_items.py and oci.py.
    spec.loader.exec_module(module)
    return module


def test_items_file_exists():
    assert ITEMS_PATH.is_file(), f"items.py not found at {ITEMS_PATH}"


@pytest.mark.parametrize("class_name", DECLARED_MODELS)
def test_declared_model_schema_builds_under_loader_import(class_name):
    module = _load_items_like_the_loader()
    model = getattr(module, class_name)
    schema = model.model_json_schema()
    assert schema["type"] == "object"
    assert "properties" in schema


def test_all_module_models_are_fully_defined():
    """Every BaseModel in items.py must build a schema, so new types can't
    silently regress."""
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


# --- Unknowable fields are optional ---


def test_share_validates_with_only_observable_fields():
    """A share reported the way an operator discovers it must validate."""
    module = _load_items_like_the_loader()
    share = module.Share.model_validate(
        {"title": "SYSVOL", "share_name": "SYSVOL", "path": r"\\dc01\SYSVOL", "permissions": "READ"}
    )
    assert share.owner is None
    assert share.size is None
    assert share.last_modified is None


def test_user_description_is_optional():
    module = _load_items_like_the_loader()
    user = module.User.model_validate({"title": "jsmith", "username": "jsmith"})
    assert user.description is None
    assert user.domain is None


# --- Host role is explicit, not inferred from field population ---


def test_host_role_is_explicit_discriminator():
    module = _load_items_like_the_loader()
    dc = module.Host.model_validate({"title": "dc01", "role": "domain_controller", "hostname": "dc01"})
    member = module.Host.model_validate(
        {
            "title": "ws01.corp.local",
            "role": "member_server",
            "hostname": "ws01",
            "fqdn": "ws01.corp.local",
            "domain_name": "corp.local",
        }
    )
    # Role is what the caller stated, regardless of which optional fields are set.
    assert dc.role == "domain_controller"
    assert member.role == "member_server"


def test_host_requires_a_role():
    module = _load_items_like_the_loader()
    with pytest.raises(ValidationError):
        module.Host.model_validate({"title": "dc01", "hostname": "dc01"})


# --- Flattened report_item schema: no cross-type field-type collisions ---


def test_shared_field_types_are_consistent_across_declared_models():
    """report_item flattens every type's fields into one schema keyed by the
    first definition, so a field name shared across types must carry the same
    JSON *shape*. Guards against reintroducing a conflicting field such as a
    list-typed description alongside a string-typed one. Human-readable
    descriptions may legitimately differ per type, so only structural keys
    are compared."""
    structural_keys = ("type", "enum", "anyOf", "items", "format", "$ref")
    module = _load_items_like_the_loader()
    seen: dict[str, str] = {}
    for class_name in DECLARED_MODELS:
        props = getattr(module, class_name).model_json_schema()["properties"]
        for field, schema in props.items():
            shape = {k: schema[k] for k in structural_keys if k in schema}
            fingerprint = str(sorted(shape.items()))
            if field in seen:
                assert seen[field] == fingerprint, f"field '{field}' has conflicting schemas across declared models"
            else:
                seen[field] = fingerprint


# --- The manifest's outputs: block actually resolves against items.py ---


def test_capability_outputs_block_resolves_to_real_models():
    """Nothing else parses capability.yaml, so a typo'd `items:ClassName` ref
    would be silently dropped by the runtime resolver — reproducing the empty
    Agent Output bug with a green suite. Parse the manifest and prove every
    declared custom type maps to a model that builds a schema, and that the
    built-in values are the ones we expect."""
    import yaml

    manifest_path = (Path(__file__).resolve().parent.parent / "capability.yaml").resolve()
    outputs = yaml.safe_load(manifest_path.read_text())["outputs"]

    assert set(outputs["values"]) == {"finding", "asset"}

    module = _load_items_like_the_loader()
    custom = {k: v for k, v in outputs.items() if k != "values"}
    assert set(custom) == {"host", "user", "credential", "hash", "share", "weakness"}

    for item_type, ref in custom.items():
        module_name, _, class_name = ref.partition(":")
        assert module_name == "items", f"{item_type} ref should point at items.py, got {ref!r}"
        model = getattr(module, class_name, None)
        assert model is not None, f"{ref} does not resolve to a class in items.py"
        assert model.model_json_schema()["type"] == "object"
