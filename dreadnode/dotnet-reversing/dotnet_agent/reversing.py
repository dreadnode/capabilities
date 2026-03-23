"""
.NET binary reversing tools using ILSpy via pythonnet.

Provides decompilation, type/method listing, reference searching,
and call flow analysis for .NET assemblies (.dll, .exe).

Order matters for .NET interop imports — pythonnet must be loaded
before CLR references are added.
"""

import typing as t
from pathlib import Path

from loguru import logger
from pythonnet import load  # type: ignore[import-untyped]

load("coreclr")

import clr  # type: ignore[import-untyped] # noqa: E402
import sys  # noqa: E402

# ILSpy DLLs — bootstrap installs them to ~/.dreadnode/dotnet-agent/lib/
LIB_DIR = Path(
    __import__("os").environ.get(
        "DOTNET_TOOLS_LIB_DIR",
        str(Path.home() / ".dreadnode" / "dotnet-agent" / "lib"),
    )
)

sys.path.append(str(LIB_DIR))

clr.AddReference("ICSharpCode.Decompiler")
clr.AddReference("Mono.Cecil")

from ICSharpCode.Decompiler import DecompilerSettings  # type: ignore[import-not-found] # noqa: E402
from ICSharpCode.Decompiler.CSharp import CSharpDecompiler  # type: ignore[import-not-found] # noqa: E402
from ICSharpCode.Decompiler.Metadata import MetadataTokenHelpers  # type: ignore[import-not-found] # noqa: E402
from ICSharpCode.Decompiler.TypeSystem import FullTypeName  # type: ignore[import-not-found] # noqa: E402
from Mono.Cecil import AssemblyDefinition  # type: ignore[import-not-found] # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _shorten_dotnet_name(name: str) -> str:
    return name.split(" ")[-1].split("(")[0]


def _get_decompiler(path: str) -> CSharpDecompiler:
    settings = DecompilerSettings()
    settings.ThrowOnAssemblyResolveErrors = False
    return CSharpDecompiler(path, settings)


def _decompile_token(path: str, token: int) -> str:
    entity_handle = MetadataTokenHelpers.TryAsEntityHandle(token.ToUInt32())  # type: ignore[attr-defined]
    return _get_decompiler(path).DecompileAsString(entity_handle)  # type: ignore[no-any-return]


def _find_references(assembly: t.Any, search: str) -> list[str]:
    flexible_search_strings = [
        search.lower(),
        search.lower().replace(".", "::"),
        search.lower().replace("::", "."),
    ]

    using_methods: set[str] = set()
    for module in assembly.Modules:
        methods = []
        for module_type in module.Types:
            for method in module_type.Methods:
                methods.append(method)

        for method in methods:
            if not method.HasBody:
                continue

            for instruction in method.Body.Instructions:
                instruction_str = str(instruction.Operand).lower()
                for _search in flexible_search_strings:
                    if _search in instruction_str:
                        using_methods.add(method.FullName)

    return list(using_methods)


def _extract_unique_call_paths(
    tree: dict[str, t.Any],
    current_path: list[str] | None = None,
) -> list[list[str]]:
    if current_path is None:
        current_path = []

    if not tree:
        return [current_path] if current_path else []

    paths = []
    for method, subtree in tree.items():
        new_path = [method, *current_path]
        paths.extend(_extract_unique_call_paths(subtree, new_path))

    return paths


# ---------------------------------------------------------------------------
# Public API — each function is a CLI command
# ---------------------------------------------------------------------------

BINARY_EXTENSIONS = {".dll", ".exe"}
DEFAULT_EXCLUDE = ["mscorlib.dll"]


def scan_binaries(
    base_path: str,
    pattern: str = "**/*",
    exclude: list[str] | None = None,
) -> list[str]:
    """Scan a directory for .NET binaries and return relative paths."""
    exclude = exclude or DEFAULT_EXCLUDE
    base = Path(base_path)
    if not base.exists():
        raise ValueError(f"Base path does not exist: {base_path}")

    binaries: list[str] = []
    for file_path in base.rglob(pattern):
        if file_path.suffix.lower() not in BINARY_EXTENSIONS:
            continue
        rel_path = str(file_path.relative_to(base))
        if not any(ex in rel_path for ex in exclude):
            binaries.append(rel_path)

    return binaries


def decompile_module(path: str) -> str:
    """Decompile the entire module and return the decompiled code."""
    logger.info(f"decompile_module({path})")
    return _get_decompiler(path).DecompileWholeModuleAsString()  # type: ignore[no-any-return]


def decompile_type(path: str, type_name: str) -> str:
    """Decompile a specific type and return the decompiled code."""
    logger.info(f"decompile_type({path}, {type_name})")
    full_type_name = FullTypeName(type_name)
    return _get_decompiler(path).DecompileTypeAsString(full_type_name)  # type: ignore[no-any-return]


def decompile_methods(path: str, method_names: list[str]) -> dict[str, str]:
    """Decompile specific methods by name and return a dict of name -> source."""
    logger.info(f"decompile_methods({path}, {method_names})")
    flexible_method_names = [
        _shorten_dotnet_name(name).lower() for name in method_names
    ]
    assembly = AssemblyDefinition.ReadAssembly(path)
    methods: dict[str, str] = {}
    for module in assembly.Modules:
        for module_type in module.Types:
            for method in module_type.Methods:
                method_name = _shorten_dotnet_name(method.FullName).lower()
                if method_name in flexible_method_names:
                    methods[method.FullName] = _decompile_token(
                        path, method.MetadataToken
                    )
    return methods


def list_namespaces(path: str) -> list[str]:
    """List all namespaces in the assembly."""
    logger.info(f"list_namespaces({path})")
    assembly = AssemblyDefinition.ReadAssembly(path)

    namespaces: set[str] = set()
    for module in assembly.Modules:
        for module_type in module.Types:
            if "." in module_type.FullName:
                namespace = ".".join(module_type.FullName.split(".")[:-1])
                namespaces.add(namespace)
            else:
                namespaces.add("<root>")

    return sorted(namespaces)


def list_types_in_namespace(path: str, namespace: str) -> list[str]:
    """List all types in the specified namespace."""
    logger.info(f"list_types_in_namespace({path}, {namespace})")
    assembly = AssemblyDefinition.ReadAssembly(path)

    types: list[str] = []
    for module in assembly.Modules:
        for module_type in module.Types:
            if namespace == "<root>":
                if "." not in module_type.FullName or (
                    module_type.FullName.count(".") == 1
                    and module_type.FullName.endswith("Module")
                ):
                    types.append(module_type.FullName)
            elif module_type.FullName.startswith(f"{namespace}."):
                remainder = module_type.FullName[len(namespace) + 1 :]
                if "." not in remainder:
                    types.append(module_type.FullName)

    return types


def list_methods_in_type(path: str, type_name: str) -> list[str]:
    """List all methods in the specified type."""
    logger.info(f"list_methods_in_type({path}, {type_name})")
    assembly = AssemblyDefinition.ReadAssembly(path)

    methods: list[str] = []
    for module in assembly.Modules:
        for module_type in module.Types:
            if module_type.FullName == type_name:
                methods.extend([method.Name for method in module_type.Methods])
                break

    return methods


def list_types(path: str) -> list[str]:
    """List all types in the assembly and return their full names."""
    logger.info(f"list_types({path})")
    assembly = AssemblyDefinition.ReadAssembly(path)
    return [
        module_type.FullName
        for module in assembly.Modules
        for module_type in module.Types
    ]


def list_methods(path: str) -> list[str]:
    """List all methods in the assembly and return their full names."""
    logger.info(f"list_methods({path})")
    assembly = AssemblyDefinition.ReadAssembly(path)
    methods: list[str] = []
    for module in assembly.Modules:
        for module_type in module.Types:
            methods.extend([method.FullName for method in module_type.Methods])
    return methods


def search_for_references(path: str, search: str) -> list[str]:
    """Find all methods that reference the search string."""
    logger.info(f"search_for_references({path}, {search})")
    assembly = AssemblyDefinition.ReadAssembly(path)
    return _find_references(assembly, search)


def search_by_name(path: str, search: str) -> dict[str, list[str]]:
    """Search for types and methods matching the search string."""
    logger.info(f"search_by_name({path}, {search})")

    results: dict[str, list[str]] = {"types": [], "methods": []}
    assembly = AssemblyDefinition.ReadAssembly(path)
    search_lower = search.lower()

    for module in assembly.Modules:
        for module_type in module.Types:
            if search_lower in module_type.FullName.lower():
                results["types"].append(module_type.FullName)

    for module in assembly.Modules:
        for module_type in module.Types:
            for method in module_type.Methods:
                if search_lower in method.FullName.lower():
                    results["methods"].append(method.FullName)

    return results


def get_call_flows_to_method(
    paths: list[str],
    method_name: str,
    max_depth: int = 10,
) -> list[list[str]]:
    """Find all unique call flows to the target method across assemblies."""
    logger.info(f"get_call_flows_to_method({paths}, {method_name})")
    assemblies = [AssemblyDefinition.ReadAssembly(path) for path in paths]
    short_target_name = _shorten_dotnet_name(method_name)

    def build_tree(
        name: str,
        current_depth: int = 0,
        visited: set[str] | None = None,
    ) -> dict[str, t.Any]:
        visited = visited or set()
        if name in visited or current_depth > max_depth:
            return {}

        visited.add(name)
        tree = {}

        for assembly in assemblies:
            for caller in _find_references(assembly, name):
                if caller not in visited:
                    tree[caller] = build_tree(
                        _shorten_dotnet_name(caller),
                        current_depth + 1,
                        visited.copy(),
                    )

        return tree

    call_tree = build_tree(short_target_name)
    return _extract_unique_call_paths(call_tree)
