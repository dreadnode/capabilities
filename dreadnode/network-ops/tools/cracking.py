import asyncio
import os
import tempfile

from dreadnode import Config
from dreadnode.agents.tools import Toolset, tool_method
from dreadnode.tools.execute import execute
from loguru import logger

g_hashcat_lock = asyncio.Lock()


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

            logger.info(
                f"Cracking {hash_file_path} with mode {hashcat_mode} using wordlist {wordlist_path}"
            )

            # Execute the cracking command
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

            # Execute the --show command to get the cracked results
            return await execute(["hashcat", "-m", str(hashcat_mode), hash_file_path, "--show"])

    @tool_method(catch=True, variants=["john", "all"])
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

        logger.info(
            f"Cracking {hash_file_path} with format {hash_format} using wordlist {wordlist_path}"
        )

        # Execute the cracking command
        # Note: John's --max-run-time is not a standard feature, we rely on the timeout
        await execute(
            [
                "john",
                f"--wordlist={wordlist_path}",
                f"--format={hash_format}",
                hash_file_path,
            ],
            timeout=(max_time_minutes * 60) + 30,
        )

        # Execute the --show command to get the cracked results
        return await execute(["john", "--show", f"--format={hash_format}", hash_file_path])
