"""
SAST capability tools.

This module exports tools specific to the SAST capability:
- FileMap: Structural code overview (classes, functions with line numbers)
- CodeSearch: Natural language code exploration sub-agent
- Git tools: diff, log, blame
- Editing tools: str_replace, insert_at_line, create_file, undo_edit
- Diff tool: snapshot-based diffing for non-git repos
- Vulnerability reporter: report confirmed vulnerabilities
- Review highlight: flag lower-confidence findings for human review
- Think: record reasoning during analysis
- Dangerous function scanners: Python, Java, Go, C/C++, C#
- CodeQL: static analysis using GitHub CodeQL
- File construction: PoC file building helpers

NOTE: Common exploration tools (glob, grep, read, ls) are provided by
the platform and do not need to be included here.
"""

from .codeql import CodeQLTool
from .codesearch import CodeSearchTool
from .dangerous_functions import (
    DangerousFunctionsBase,
    DangerousFunctionsCCppTool,
    DangerousFunctionsCSharpTool,
    DangerousFunctionsGoTool,
    DangerousFunctionsJavaTool,
    DangerousFunctionsPythonTool,
)
from .diff import DiffTool
from .editing import EditTool
from .exploration import FileMapTool
from .file_construction import ASN1BuilderTool, FileConstructionLibrariesTool
from .git_tools import GitTool
from .review_highlight import (
    ReviewHighlight,
    ReviewHighlightReport,
    ReviewHighlightTool,
    ReviewPriority,
)
from .think import think
from .vulnerability_reporter import (
    Vulnerability,
    VulnerabilityReport,
    VulnerabilityReporter,
    VulnerabilitySeverity,
)

__all__ = [
    # File structure overview
    "FileMapTool",
    # CodeSearch sub-agent
    "CodeSearchTool",
    # Git
    "GitTool",
    # Editing
    "EditTool",
    # Diff (non-git repos)
    "DiffTool",
    # Reporting
    "VulnerabilityReporter",
    "Vulnerability",
    "VulnerabilityReport",
    "VulnerabilitySeverity",
    # Review highlights
    "ReviewHighlightTool",
    "ReviewHighlight",
    "ReviewHighlightReport",
    "ReviewPriority",
    # Reasoning
    "think",
    # Dangerous Functions
    "DangerousFunctionsBase",
    "DangerousFunctionsPythonTool",
    "DangerousFunctionsJavaTool",
    "DangerousFunctionsGoTool",
    "DangerousFunctionsCCppTool",
    "DangerousFunctionsCSharpTool",
    # CodeQL
    "CodeQLTool",
    # File construction helpers
    "FileConstructionLibrariesTool",
    "ASN1BuilderTool",
]
