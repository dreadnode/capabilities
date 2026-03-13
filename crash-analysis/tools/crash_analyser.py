"""Crash analysis tools for C/C++ binaries.

Provides automated crash analysis using gdb/lldb, with stack trace
extraction, register dumps, memory examination, and crash classification.

Derived from: github.com/gadievron/raptor (packages/binary_analysis)
Original authors: Gadi Evron, Daniel Cuthbert, Thomas Dullien, Michael Bargury, John Cartwright
"""

import hashlib
import shutil
import subprocess
import typing as t
from pathlib import Path

from dreadnode.agents.tools import Toolset, tool_method
from pydantic import PrivateAttr


class CrashAnalysis(Toolset):
    """Analyze crashes in C/C++ binaries using gdb or lldb."""

    binary_path: str = ""
    """Path to the binary to analyze. Set before calling analysis methods."""

    timeout: int = 30
    """Timeout for debugger commands in seconds."""

    _debugger: str = PrivateAttr(default="")

    def model_post_init(self, __context: t.Any) -> None:
        super().model_post_init(__context)
        self._debugger = self._detect_debugger()

    def _detect_debugger(self) -> str:
        """Detect available debugger (gdb preferred, lldb fallback)."""
        if shutil.which("gdb"):
            return "gdb"
        if shutil.which("lldb"):
            return "lldb"
        return ""

    def _run_gdb(self, commands: list[str], input_file: str | None = None) -> str:
        """Run gdb with a list of commands and return output."""
        if not self.binary_path:
            return "Error: binary_path not set"

        cmd_str = "\n".join(commands)
        gdb_cmd = ["gdb", "-batch", "-nx"]
        gdb_cmd += ["-ex", f"file {self.binary_path}"]

        if input_file:
            gdb_cmd += ["-ex", f"run < {input_file}"]
        else:
            gdb_cmd += ["-ex", "run"]

        for c in commands:
            gdb_cmd += ["-ex", c]

        try:
            result = subprocess.run(
                gdb_cmd, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"GDB timed out after {self.timeout}s"
        except FileNotFoundError:
            return "Error: gdb not found"

    @tool_method
    def analyze_crash(
        self,
        input_file: t.Annotated[str, "Path to the input file that triggers the crash"],
        signal: t.Annotated[str, "Signal that caused the crash (e.g. SIGSEGV, SIGABRT)"] = "SIGSEGV",
    ) -> str:
        """Analyze a crash by running the binary under gdb and extracting diagnostics.

        Returns stack trace, registers, crash instruction, and crash classification.
        """
        if not self.binary_path:
            return "Error: set binary_path before calling analyze_crash"
        if not Path(self.binary_path).exists():
            return f"Error: binary not found at {self.binary_path}"
        if not Path(input_file).exists():
            return f"Error: input file not found at {input_file}"

        if self._debugger == "gdb":
            output = self._run_gdb(
                ["bt full", "info registers", "x/10i $pc", "info locals"],
                input_file=input_file,
            )
        elif self._debugger == "lldb":
            output = self._run_lldb(input_file)
        else:
            return "Error: no debugger available (install gdb or lldb)"

        # Classify crash type from output
        crash_type = self._classify(output)
        stack_hash = self._hash_stack(output)

        return (
            f"Signal: {signal}\n"
            f"Crash type: {crash_type}\n"
            f"Stack hash: {stack_hash}\n"
            f"Debugger: {self._debugger}\n\n"
            f"--- Debugger Output ---\n{output}"
        )

    def _run_lldb(self, input_file: str) -> str:
        """Run lldb to analyze crash."""
        cmd = [
            "lldb", "-b",
            "-o", f"target create {self.binary_path}",
            "-o", f"process launch --stdin {input_file}",
            "-o", "bt all",
            "-o", "register read",
            "-o", "disassemble --pc",
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return f"LLDB timed out after {self.timeout}s"
        except FileNotFoundError:
            return "Error: lldb not found"

    @tool_method
    def get_backtrace(
        self,
        input_file: t.Annotated[str, "Path to crash-triggering input file"],
    ) -> str:
        """Get stack trace for a crash."""
        if not self.binary_path:
            return "Error: set binary_path first"
        return self._run_gdb(["bt full"], input_file=input_file)

    @tool_method
    def examine_memory(
        self,
        address: t.Annotated[str, "Memory address to examine (hex, e.g. 0x7fff5fbff8c0)"],
        num_bytes: t.Annotated[int, "Number of bytes to examine"] = 64,
        input_file: t.Annotated[str | None, "Optional crash input file to run first"] = None,
    ) -> str:
        """Examine memory at a given address using gdb."""
        if not self.binary_path:
            return "Error: set binary_path first"
        return self._run_gdb(
            [f"x/{num_bytes}xb {address}"],
            input_file=input_file,
        )

    @tool_method
    def get_binary_info(self) -> str:
        """Get basic information about the binary (file type, architecture, protections)."""
        if not self.binary_path:
            return "Error: set binary_path first"
        if not Path(self.binary_path).exists():
            return f"Error: {self.binary_path} not found"

        lines: list[str] = []

        # file command
        try:
            r = subprocess.run(
                ["file", self.binary_path], capture_output=True, text=True, timeout=10
            )
            lines.append(f"File: {r.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # checksec if available
        try:
            r = subprocess.run(
                ["checksec", "--format=csv", "--file", self.binary_path],
                capture_output=True, text=True, timeout=10,
            )
            if r.returncode == 0:
                lines.append(f"Checksec: {r.stdout.strip()}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # ASAN detection
        try:
            r = subprocess.run(
                ["nm", "-D", self.binary_path],
                capture_output=True, text=True, timeout=10,
            )
            if "__asan" in r.stdout:
                lines.append("AddressSanitizer: detected")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return "\n".join(lines) if lines else "No binary info available"

    def _classify(self, debugger_output: str) -> str:
        """Classify crash type from debugger output."""
        out = debugger_output.lower()
        if "heap-buffer-overflow" in out or "heap-use-after-free" in out:
            return "heap_corruption"
        if "stack-buffer-overflow" in out:
            return "stack_overflow"
        if "null" in out and ("deref" in out or "access" in out or "0x0" in out):
            return "null_dereference"
        if "use-after-free" in out or "dangling" in out:
            return "use_after_free"
        if "double-free" in out:
            return "double_free"
        if "sigabrt" in out:
            return "abort"
        if "sigsegv" in out:
            return "segfault"
        return "unknown"

    def _hash_stack(self, debugger_output: str) -> str:
        """Compute deduplication hash from stack trace."""
        # Extract function names from backtrace
        import re
        frames = re.findall(r"#\d+\s+(?:0x[0-9a-f]+\s+in\s+)?(\S+)", debugger_output)
        if not frames:
            return ""
        key = "|".join(frames[:10])
        return hashlib.sha256(key.encode()).hexdigest()[:16]
