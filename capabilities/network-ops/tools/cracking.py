import asyncio
import os
import re
import tempfile

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger

g_hashcat_lock = asyncio.Lock()

HASHCAT_TO_JOHN: dict[int, str] = {
    1000: "nt",
    2100: "mscash2",
    13100: "krb5tgs",
    18200: "krb5asrep",
}

_NO_BACKEND_MARKERS = ("CL_PLATFORM_NOT_FOUND_KHR", "No devices found/left")

# hashcat exit statuses that mean the run started and then stopped for an
# expected reason: 1 = keyspace exhausted, 2/3 = aborted, 4 = halted by the
# --runtime time box this tool always sets. In each the potfile may already
# hold cracked hashes, so results are collected rather than treated as failure.
# Anything else (255, negative) means hashcat could not run and is surfaced.
_HASHCAT_RAN_EXIT_CODES = frozenset({1, 2, 3, 4})

_EXECUTE_EXIT_CODE_RE = re.compile(r"Command failed \((-?\d+)\)")


def _execute_exit_code(message: str) -> int | None:
    """Recover the process exit code the platform execute() helper embeds in its
    failure text ("Command failed (<code>): ..."), or None when it is absent."""
    match = _EXECUTE_EXIT_CODE_RE.search(message)
    return int(match.group(1)) if match else None


class Cracking(Toolset):
    """
    Toolset for password cracking using Hashcat and/or John the Ripper.
    """

    variant: str | None = Config(default="hashcat")
    """Which cracking tools to enable."""

    @tool_method(catch=True, variants=["hashcat", "all"])
    async def hashcat(
        self,
        hashcat_mode: int,
        hashes: list[str] | None = None,
        hash_file: str | None = None,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 2,
    ) -> str:
        """
        Attempts to crack a list of password hashes using hashcat.

        One of `hashes` or `hash_file` must be provided.

        Args:
            hashcat_mode: The hashcat mode to use (e.g., 13100 for Kerberoas, 18200 for AS-REP).
            hashes: A list of hashes to crack.
            hash_file: A path to a file containing hashes to crack.
            wordlist_path: The path to the wordlist file.
            max_time_minutes: The maximum time (in minutes) to spend cracking.

        Returns:
            A string containing the cracked passwords.
        """
        async with g_hashcat_lock:
            if hashes is not None:
                _, hash_file_path = tempfile.mkstemp(suffix=".hashes")
                with open(hash_file_path, "w") as f:  # noqa: ASYNC230
                    f.write("\n".join(hashes))
            elif hash_file is not None:
                hash_file_path = hash_file
            else:
                raise ValueError("Either 'hashes' or 'hash_file' must be provided.")

            if not os.path.exists(hash_file_path):
                raise FileNotFoundError(f"Hash file {hash_file_path} does not exist.")

            if not os.path.exists(wordlist_path):
                raise FileNotFoundError(f"Wordlist file {wordlist_path} does not exist.")

            logger.info(f"Cracking {hash_file_path} with mode {hashcat_mode} using wordlist {wordlist_path}")

            # Run the crack, then always read the potfile with --show below. hashcat
            # records each recovered hash to the potfile as it goes and a time-boxed
            # crack normally exits non-zero (keyspace exhausted, or halted by the
            # --runtime box), so an expected non-zero exit, or a timeout that kills the
            # process, must not abort before --show collects what landed. A crack that
            # could not run (no compute backend, or any other genuine failure) is
            # surfaced instead, so an empty result never masks a broken invocation.
            try:
                await execute(
                    [
                        "hashcat",
                        "-m",
                        str(hashcat_mode),
                        "-a",
                        "0",
                        hash_file_path,
                        wordlist_path,
                        "--runtime",
                        str(max_time_minutes * 60),
                        "--force",
                    ],
                    timeout=(max_time_minutes * 60) + 30,
                )
            except TimeoutError:
                logger.info("hashcat crack step timed out; collecting recovered hashes from " "the potfile via --show")
            except RuntimeError as e:
                msg = str(e)
                if any(marker in msg for marker in _NO_BACKEND_MARKERS):
                    john_fmt = HASHCAT_TO_JOHN.get(hashcat_mode)
                    if john_fmt:
                        raise RuntimeError(
                            f"hashcat failed: no OpenCL/CUDA/HIP backend available. "
                            f"Use john_the_ripper instead with hash_format='{john_fmt}'."
                        ) from e
                    raise RuntimeError(
                        f"hashcat failed: no OpenCL/CUDA/HIP backend available. "
                        f"Use john_the_ripper instead (hashcat mode {hashcat_mode} "
                        f"has no automatic john format mapping — consult john documentation)."
                    ) from e
                if _execute_exit_code(msg) not in _HASHCAT_RAN_EXIT_CODES:
                    raise
                logger.info(
                    "hashcat crack step exited non-zero (exhausted or aborted); "
                    "collecting recovered hashes from the potfile via --show"
                )

            return await execute(["hashcat", "-m", str(hashcat_mode), hash_file_path, "--show"])

    @tool_method(catch=True, variants=["hashcat", "john", "all"])
    async def john_the_ripper(
        self,
        hash_format: str,
        hashes: list[str] | None = None,
        hash_file: str | None = None,
        wordlist_path: str = "/usr/share/wordlists/rockyou.txt",
        max_time_minutes: int = 10,
    ) -> str:
        """
        Attempts to crack a list of password hashes using John the Ripper.

        One of `hashes` or `hash_file` must be provided.

        Args:
            hash_format: The John hash format (e.g., 'krb5asrep', 'krb5tgs', 'ntlm').
            hashes: A list of hashes to crack.
            hash_file: A path to a file containing hashes to crack.
            wordlist_path: The path to the wordlist file.
            max_time_minutes: The maximum time (in minutes) to spend cracking.

        Returns:
            A string containing the cracked passwords.
        """
        if hashes is not None:
            _, hash_file_path = tempfile.mkstemp(suffix=".hashes")
            with open(hash_file_path, "w") as f:  # noqa: ASYNC230
                f.write("\n".join(hashes))
        elif hash_file is not None:
            hash_file_path = hash_file
        else:
            raise ValueError("Either 'hashes' or 'hash_file' must be provided.")

        if not os.path.exists(hash_file_path):
            raise FileNotFoundError(f"Hash file {hash_file_path} does not exist.")

        if not os.path.exists(wordlist_path):
            raise FileNotFoundError(f"Wordlist file {wordlist_path} does not exist.")

        logger.info(f"Cracking {hash_file_path} with format {hash_format} using wordlist {wordlist_path}")

        # Run the crack, then read the pot file with --show below. John writes each
        # recovered password to its pot file as it goes and is time-boxed here by the
        # run timeout, so a run cut short by the time box still has results to collect.
        # A non-zero exit means john itself failed (bad format, unreadable hashes) and
        # is left to surface rather than reported as an empty, successful result.
        try:
            await execute(
                [
                    "john",
                    f"--wordlist={wordlist_path}",
                    f"--format={hash_format}",
                    hash_file_path,
                ],
                timeout=(max_time_minutes * 60) + 30,
            )
        except TimeoutError:
            logger.info("john crack step timed out; collecting recovered hashes from the " "pot file via --show")

        return await execute(["john", "--show", f"--format={hash_format}", hash_file_path])
