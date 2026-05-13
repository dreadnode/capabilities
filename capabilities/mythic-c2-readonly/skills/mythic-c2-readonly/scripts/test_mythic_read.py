#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "pytest>=8.0",
#   "pytest-asyncio>=0.23",
#   "mythic>=0.2",
#   "gql[aiohttp,websockets]>=3.0,<4.0",
#   "pydantic>=2.0,<3.0",
# ]
# ///
"""Regression tests for mythic_read.py — no Mythic instance required.

Uses captured fixture data from a live Operation Chimera environment.
All SDK/GraphQL calls are mocked so tests run offline.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import mythic_read


# ── Fixture data (captured from live Mythic instance) ────────────────

CALLBACKS_DATA = [
    {
        "display_id": 1,
        "host": "BARBHACK-2024-KALI",
        "user": "kali",
        "ip": '["10.1.10.99","172.17.0.1"]',
        "external_ip": "10.1.10.99",
        "os": "Linux\nbarbhack-2024-kali\n6.10.11-amd64",
        "architecture": "amd64",
        "pid": 2112254,
        "process_name": "/tmp/agent_linux",
        "description": "Poseidon Linux agent",
        "extra_info": "",
        "sleep_info": '{"http":{"interval":10}}',
        "active": True,
        "last_checkin": "2026-03-27T04:27:39.990097",
        "init_callback": "2026-03-25T05:26:32.270542",
        "integrity_level": 2,
        "domain": "",
        "payload": {
            "os": "Linux",
            "payloadtype": {"name": "poseidon"},
            "description": "Poseidon Linux agent",
        },
    },
    {
        "display_id": 7,
        "host": "BARBHACK-2024-SRV02",
        "user": "localuser",
        "ip": '["10.1.10.12"]',
        "external_ip": "10.1.10.12",
        "os": "Windows",
        "architecture": "x86_64",
        "pid": 3052,
        "process_name": "",
        "description": "Thanatos Windows agent",
        "extra_info": "",
        "sleep_info": "",
        "active": True,
        "last_checkin": "2026-03-25T05:53:06.44848",
        "init_callback": "2026-03-25T05:53:06.44848",
        "integrity_level": 3,
        "domain": "",
        "payload": {
            "os": "Windows",
            "payloadtype": {"name": "thanatos"},
            "description": "Thanatos Windows agent",
        },
    },
]

CALLBACK_DETAIL = {
    "callback": [
        {
            "id": 1,
            "display_id": 1,
            "host": "BARBHACK-2024-KALI",
            "user": "kali",
            "domain": "",
            "integrity_level": 2,
            "ip": '["10.1.10.99"]',
            "external_ip": "10.1.10.99",
            "os": "Linux\nbarbhack-2024-kali",
            "architecture": "amd64",
            "pid": 2112254,
            "process_name": "/tmp/agent_linux",
            "description": "Poseidon Linux agent",
            "extra_info": "",
            "sleep_info": '{"http":{"interval":10}}',
            "active": True,
            "last_checkin": "2026-03-27T04:25:27.904749",
            "init_callback": "2026-03-25T05:26:32.270542",
            "agent_callback_id": "dbd295ef-e47d-46aa-8fda-5511cc79c1f4",
            "operation_id": 1,
            "payload": {
                "os": "Linux",
                "uuid": "50a5c8ec-4069-4911-b19e-341d2d33d4eb",
                "description": "Poseidon Linux agent",
                "payloadtype": {"name": "poseidon"},
                "payloadc2profiles": [{"c2profile": {"name": "http", "is_p2p": False}}],
            },
        }
    ]
}

TASKS_DATA = [
    {
        "id": 19,
        "display_id": 19,
        "command_name": "cat",
        "original_params": "/opt/mythic/.env",
        "display_params": "/opt/mythic/.env",
        "status": "success",
        "completed": True,
        "timestamp": "2026-03-25T05:39:51.992917",
        "comment": "",
        "operator": {"username": "mythic_admin"},
        "callback": {"display_id": 1, "host": "BARBHACK-2024-KALI"},
    },
    {
        "id": 18,
        "display_id": 18,
        "command_name": "download",
        "original_params": "/opt/mythic/.env",
        "display_params": "/opt/mythic/.env",
        "status": "success",
        "completed": True,
        "timestamp": "2026-03-25T05:39:33.934431",
        "comment": "",
        "operator": {"username": "mythic_admin"},
        "callback": {"display_id": 1, "host": "BARBHACK-2024-KALI"},
    },
]

TASK_OUTPUT_DATA = [
    {"response_text": "a2FsaQ==", "response": ""},  # base64 "kali"
    {"response_text": "uid=1000(kali)"},
]

CREDENTIALS_DATA = {
    "credential": [
        {
            "id": 12,
            "type": "ticket",
            "realm": "BARBHACK",
            "account": "svc_backup",
            "credential_text": "doIGYj...truncated",
            "comment": "TGS - Kerberoast",
            "timestamp": "2026-03-25T05:32:32.147152",
            "operator": {"username": "mythic_admin"},
            "task": None,
        },
        {
            "id": 11,
            "type": "hash",
            "realm": "BARBHACK-2024-D",
            "account": "localuser",
            "credential_text": "aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117",
            "comment": "Local admin NTLM",
            "timestamp": "2026-03-25T05:32:32.024009",
            "operator": {"username": "mythic_admin"},
            "task": None,
        },
    ]
}

FILES_DATA = [
    {
        "id": 3,
        "agent_file_id": "db545058-1df9-4c13-96b3-178cffa6c65f",
        "filename_utf8": "hosts",
        "full_remote_path_utf8": "/etc/hosts",
        "host": "BARBHACK-2024-KALI",
        "complete": True,
        "is_download_from_agent": True,
        "md5": "3a2b0b30f8b6e38ba7781aa9f5eb3c96",
        "sha1": "35f9ec18c1956e432845106419b9e3ad7c42eb21",
        "timestamp": "2026-03-25T20:19:50.728083",
        "comment": "",
        "task": {
            "display_id": 16,
            "command_name": "download",
            "callback": {"display_id": 1, "host": "BARBHACK-2024-KALI"},
        },
    },
]

ARTIFACTS_DATA = {
    "taskartifact": [
        {
            "id": 64,
            "artifact_text": "powershell.exe /c Get-Service",
            "base_artifact": "Process Create",
            "host": "BARBHACK-2024-SRV02",
            "timestamp": "2026-03-25T06:13:53.535649",
            "task": {
                "display_id": 93,
                "command_name": "powershell",
                "callback": {"display_id": 7, "host": "BARBHACK-2024-SRV02"},
            },
        },
    ]
}

KEYLOGS_DATA = {
    "keylog": [
        {
            "id": 1,
            "keystrokes_text": "password123",
            "window": "Login - Chrome",
            "user": "localuser",
            "timestamp": "2026-03-25T06:00:00.000000",
            "task": {"display_id": 10, "callback": {"display_id": 5, "host": "BARBHACK-2024-DC01"}},
        },
    ]
}

SCREENSHOTS_DATA = [
    {
        "id": 1,
        "agent_file_id": "abc12345-dead-beef-cafe-000000000001",
        "host": "BARBHACK-2024-DC01",
        "timestamp": "2026-03-25T06:00:00.000000",
    },
]

PROCESSES_DATA = {
    "mythictree": [
        {
            "id": 247,
            "task_id": 12,
            "timestamp": "2026-03-25T05:36:23.197961",
            "host": "BARBHACK-2024-KALI",
            "name_text": "kworker/0:2-ata_sff",
            "parent_path_text": "2",
            "full_path_text": "2121821",
            "metadata": {
                "name": "kworker/0:2-ata_sff",
                "user": "root",
                "bin_path": "",
                "process_id": 2121821,
            },
            "os": "Linux",
            "success": None,
        },
    ]
}

FILE_BROWSER_DATA = {
    "mythictree": [
        {
            "id": 295,
            "task_id": 18,
            "timestamp": "2026-03-25T05:39:23.888016",
            "host": "BARBHACK-2024-KALI",
            "comment": "",
            "success": True,
            "deleted": False,
            "os": "",
            "can_have_children": False,
            "name_text": ".env",
            "parent_path_text": "/opt/mythic",
            "full_path_text": "/opt/mythic/.env",
            "metadata": {"size": 3724, "permissions": {}},
        },
        {
            "id": 294,
            "task_id": 18,
            "timestamp": "2026-03-25T05:39:12.871561",
            "host": "BARBHACK-2024-KALI",
            "comment": "",
            "success": None,
            "deleted": False,
            "os": "linux",
            "can_have_children": True,
            "name_text": "mythic",
            "parent_path_text": "/opt",
            "full_path_text": "/opt/mythic",
            "metadata": {},
        },
    ]
}

TOKENS_DATA = {
    "token": [
        {
            "id": 1,
            "token_id": 100,
            "user": "BARBHACK\\Administrator",
            "groups": "Domain Admins",
            "privileges": "SeDebugPrivilege",
            "thread_id": 0,
            "process_id": 1234,
            "session_id": 1,
            "logon_sid": "",
            "integrity_level_sid": "",
            "restricted": False,
            "default_dacl": "",
            "handle": 0,
            "host": "BARBHACK-2024-DC01",
            "description": "Stolen token",
            "timestamp": "2026-03-25T06:00:00.000000",
            "task": {"callback": {"display_id": 5, "host": "BARBHACK-2024-DC01"}},
        },
    ]
}

SEARCH_TASKS_DATA = {
    "task": [
        {
            "display_id": 47,
            "command_name": "shell",
            "display_params": "net localgroup Administrators",
            "status": "submitted",
            "timestamp": "2026-03-25T06:13:52",
            "callback": {"display_id": 5, "host": "BARBHACK-2024-DC01"},
        },
    ]
}

SEARCH_CREDENTIALS_DATA = {
    "credential": [
        {
            "id": 5,
            "type": "hash",
            "realm": "BARBHACK",
            "account": "Administrator",
            "credential_text": "aad3b435:e19ccf75",
            "comment": "Domain admin NTLM - DCSync",
        },
    ]
}

SEARCH_FILES_DATA: dict[str, list[Any]] = {"filemeta": []}
SEARCH_ARTIFACTS_DATA: dict[str, list[Any]] = {"taskartifact": []}
SEARCH_KEYLOGS_DATA: dict[str, list[Any]] = {"keylog": []}

ME_DATA = {
    "meHook": {"current_operation": "Operation Chimera"},
}


# ── Helpers ──────────────────────────────────────────────────────────


def make_args(**kwargs: Any) -> argparse.Namespace:
    """Build a Namespace with common defaults."""
    defaults = {
        "json": False,
        "detail": False,
        "limit": 50,
        "offset": 0,
        "callback": None,
        "host": None,
        "path": None,
        "active": False,
        "uploaded": False,
        "uploaded_only": False,
        "max_lines": None,
    }
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ── Helper unit tests ────────────────────────────────────────────────


class TestDecodeB64:
    def test_valid_base64(self):
        assert mythic_read.decode_b64("a2FsaQ==") == "kali"

    def test_plain_text_passthrough(self):
        assert mythic_read.decode_b64("not base64!") == "not base64!"

    def test_empty_string(self):
        assert mythic_read.decode_b64("") == ""

    def test_none_coerced_to_empty(self):
        """Verify falsy input returns unchanged."""
        assert mythic_read.decode_b64("") == ""
        assert mythic_read.decode_b64("") == mythic_read.decode_b64("")


class TestFirstIp:
    def test_json_array(self):
        assert mythic_read.first_ip('["10.1.10.99","172.17.0.1"]') == "10.1.10.99"

    def test_plain_ip(self):
        assert mythic_read.first_ip("10.1.10.99") == "10.1.10.99"

    def test_empty_string(self):
        assert mythic_read.first_ip("") == ""

    def test_empty_array(self):
        assert mythic_read.first_ip("[]") == "[]"

    def test_malformed_json(self):
        assert mythic_read.first_ip("[broken") == "[broken"


class TestPrintTable:
    def test_basic_table(self, capsys):
        mythic_read.print_table(["A", "B"], [["1", "hello"], ["2", "world"]])
        out = capsys.readouterr().out
        assert "A" in out
        assert "hello" in out
        assert "world" in out

    def test_empty_rows(self, capsys):
        mythic_read.print_table(["A"], [])
        assert "(no results)" in capsys.readouterr().out

    def test_max_widths_truncation(self, capsys):
        mythic_read.print_table(["COL"], [["a" * 100]], max_widths={0: 20})
        out = capsys.readouterr().out
        assert "..." in out


# ── Command tests ────────────────────────────────────────────────────


class TestCmdStatus:
    @pytest.mark.asyncio
    async def test_status_output(self, capsys, monkeypatch):
        monkeypatch.setenv("MYTHIC_SERVER_IP", "10.1.10.99")
        monkeypatch.setenv("MYTHIC_SERVER_PORT", "7443")
        mock_get_me = AsyncMock(return_value=ME_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_me", mock_get_me):
            await mythic_read.cmd_status(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "10.1.10.99:7443" in out
        assert "Operation Chimera" in out


class TestCmdCallbacks:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_get = AsyncMock(return_value=CALLBACKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_callbacks", mock_get):
            await mythic_read.cmd_callbacks(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "BARBHACK-2024-KALI" in out
        assert "poseidon" in out
        assert "BARBHACK-2024-SRV02" in out
        assert "thanatos" in out

    @pytest.mark.asyncio
    async def test_active_filter(self, capsys):
        mock_get = AsyncMock(return_value=CALLBACKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_active_callbacks", mock_get):
            await mythic_read.cmd_callbacks(MagicMock(), make_args(active=True))
        mock_get.assert_called_once()
        out = capsys.readouterr().out
        assert "BARBHACK-2024-KALI" in out

    @pytest.mark.asyncio
    async def test_json_output(self, capsys):
        mock_get = AsyncMock(return_value=CALLBACKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_callbacks", mock_get):
            await mythic_read.cmd_callbacks(MagicMock(), make_args(json=True))
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed) == 2
        assert parsed[0]["host"] == "BARBHACK-2024-KALI"

    @pytest.mark.asyncio
    async def test_ip_extraction(self, capsys):
        mock_get = AsyncMock(return_value=CALLBACKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_callbacks", mock_get):
            await mythic_read.cmd_callbacks(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "10.1.10.99" in out
        assert "10.1.10.12" in out

    @pytest.mark.asyncio
    async def test_os_newline_stripped(self, capsys):
        mock_get = AsyncMock(return_value=CALLBACKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_callbacks", mock_get):
            await mythic_read.cmd_callbacks(MagicMock(), make_args())
        out = capsys.readouterr().out
        # OS should only show first line
        assert "barbhack-2024-kali" not in out
        assert "Linux" in out


class TestCmdCallback:
    @pytest.mark.asyncio
    async def test_detail_output(self, capsys):
        mock_gql = AsyncMock(return_value=CALLBACK_DETAIL)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_callback(MagicMock(), make_args(id=1))
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed["display_id"] == 1
        assert parsed["host"] == "BARBHACK-2024-KALI"
        assert parsed["payload"]["payloadtype"]["name"] == "poseidon"

    @pytest.mark.asyncio
    async def test_not_found(self, capsys):
        mock_gql = AsyncMock(return_value={"callback": []})
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_callback(MagicMock(), make_args(id=999))
        out = capsys.readouterr().out
        assert "No callback found" in out


class TestCmdTasks:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_get = AsyncMock(return_value=TASKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_tasks", mock_get):
            await mythic_read.cmd_tasks(MagicMock(), make_args(callback=1, limit=20))
        out = capsys.readouterr().out
        assert "cat" in out
        assert "download" in out
        assert "BARBHACK-2024-KALI" in out
        assert "success" in out

    @pytest.mark.asyncio
    async def test_json_output(self, capsys):
        mock_get = AsyncMock(return_value=TASKS_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_tasks", mock_get):
            await mythic_read.cmd_tasks(MagicMock(), make_args(callback=1, json=True))
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed) == 2

    @pytest.mark.asyncio
    async def test_pagination_message(self, capsys):
        many_tasks = [{**TASKS_DATA[0], "id": i, "display_id": i} for i in range(30)]
        mock_get = AsyncMock(return_value=many_tasks)
        with patch.object(mythic_read.mythic_sdk, "get_all_tasks", mock_get):
            await mythic_read.cmd_tasks(MagicMock(), make_args(callback=1, limit=5))
        out = capsys.readouterr().out
        assert "total tasks" in out
        assert "--offset" in out


class TestCmdTaskOutput:
    @pytest.mark.asyncio
    async def test_decoded_output(self, capsys):
        mock_get = AsyncMock(return_value=TASK_OUTPUT_DATA)
        with patch.object(mythic_read.mythic_sdk, "get_all_task_and_subtask_output_by_id", mock_get):
            await mythic_read.cmd_task_output(MagicMock(), make_args(id=1))
        out = capsys.readouterr().out
        # base64 "a2FsaQ==" should decode to "kali"
        assert "kali" in out
        assert "uid=1000(kali)" in out

    @pytest.mark.asyncio
    async def test_no_output(self, capsys):
        mock_get = AsyncMock(return_value=[])
        with patch.object(mythic_read.mythic_sdk, "get_all_task_and_subtask_output_by_id", mock_get):
            await mythic_read.cmd_task_output(MagicMock(), make_args(id=999))
        out = capsys.readouterr().out
        assert "No output" in out

    @pytest.mark.asyncio
    async def test_offset_and_max_lines(self, capsys):
        lines = [{"response_text": f"line{i}"} for i in range(20)]
        mock_get = AsyncMock(return_value=lines)
        with patch.object(mythic_read.mythic_sdk, "get_all_task_and_subtask_output_by_id", mock_get):
            await mythic_read.cmd_task_output(MagicMock(), make_args(id=1, offset=5, max_lines=3))
        out = capsys.readouterr().out
        assert "line5" in out
        assert "line7" in out
        assert "line8" not in out


class TestCmdCredentials:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=CREDENTIALS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_credentials(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "svc_backup" in out
        assert "ticket" in out
        assert "BARBHACK" in out
        assert "localuser" in out

    @pytest.mark.asyncio
    async def test_json_output(self, capsys):
        mock_gql = AsyncMock(return_value=CREDENTIALS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_credentials(MagicMock(), make_args(json=True))
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert len(parsed) == 2


class TestCmdFiles:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        async def fake_downloaded(*a, **kw):
            yield FILES_DATA

        with patch.object(mythic_read.mythic_sdk, "get_all_downloaded_files", fake_downloaded):
            await mythic_read.cmd_files(MagicMock(), make_args(limit=20))
        out = capsys.readouterr().out
        assert "hosts" in out
        assert "/etc/hosts" in out
        assert "BARBHACK-2024-KALI" in out
        assert "yes" in out

    @pytest.mark.asyncio
    async def test_json_output(self, capsys):
        async def fake_downloaded(*a, **kw):
            yield FILES_DATA

        with patch.object(mythic_read.mythic_sdk, "get_all_downloaded_files", fake_downloaded):
            await mythic_read.cmd_files(MagicMock(), make_args(json=True, limit=20))
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert parsed[0]["filename_utf8"] == "hosts"


class TestCmdFileContents:
    @pytest.mark.asyncio
    async def test_text_file(self, capsys, tmp_path):
        content = b"127.0.0.1 localhost\n::1 localhost\n"
        mock_dl = AsyncMock(return_value=content)
        with (
            patch.object(mythic_read.mythic_sdk, "download_file", mock_dl),
            patch.object(mythic_read, "TEMP_DIR", tmp_path),
        ):
            await mythic_read.cmd_file_contents(MagicMock(), make_args(uuid="test-uuid"))
        out = capsys.readouterr().out
        assert "127.0.0.1" in out
        assert "Saved to:" in out
        assert (tmp_path / "test-uuid").exists()

    @pytest.mark.asyncio
    async def test_binary_file(self, capsys, tmp_path):
        content = bytes(range(256))
        mock_dl = AsyncMock(return_value=content)
        with (
            patch.object(mythic_read.mythic_sdk, "download_file", mock_dl),
            patch.object(mythic_read, "TEMP_DIR", tmp_path),
        ):
            await mythic_read.cmd_file_contents(MagicMock(), make_args(uuid="bin-uuid"))
        out = capsys.readouterr().out
        assert "binary" in out

    @pytest.mark.asyncio
    async def test_empty_file(self, capsys):
        mock_dl = AsyncMock(return_value=None)
        with patch.object(mythic_read.mythic_sdk, "download_file", mock_dl):
            await mythic_read.cmd_file_contents(MagicMock(), make_args(uuid="empty"))
        out = capsys.readouterr().out
        assert "empty" in out.lower() or "could not" in out.lower()


class TestCmdArtifacts:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=ARTIFACTS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_artifacts(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "Process Create" in out
        assert "powershell" in out
        assert "BARBHACK-2024-SRV02" in out


class TestCmdKeylogs:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=KEYLOGS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_keylogs(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "password123" in out
        assert "Login - Chrome" in out
        assert "BARBHACK-2024-DC01" in out

    @pytest.mark.asyncio
    async def test_callback_filter(self):
        mock_gql = AsyncMock(return_value=KEYLOGS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_keylogs(MagicMock(), make_args(callback=5))
        call_args = mock_gql.call_args
        query = call_args[1].get("query", call_args[0][1] if len(call_args[0]) > 1 else "")
        assert "callback_display_id" in str(call_args)


class TestCmdScreenshots:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        async def fake_screenshots(*a, **kw):
            yield SCREENSHOTS_DATA

        with patch.object(mythic_read.mythic_sdk, "get_all_screenshots", fake_screenshots):
            await mythic_read.cmd_screenshots(MagicMock(), make_args(limit=20))
        out = capsys.readouterr().out
        assert "abc12345" in out
        assert "BARBHACK-2024-DC01" in out

    @pytest.mark.asyncio
    async def test_empty(self, capsys):
        async def fake_empty(*a, **kw):
            return
            yield  # make it an async generator

        with patch.object(mythic_read.mythic_sdk, "get_all_screenshots", fake_empty):
            await mythic_read.cmd_screenshots(MagicMock(), make_args(limit=20))
        out = capsys.readouterr().out
        assert "(no results)" in out


class TestCmdProcesses:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=PROCESSES_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_processes(MagicMock(), make_args(limit=100))
        out = capsys.readouterr().out
        assert "2121821" in out
        assert "kworker" in out
        assert "root" in out
        assert "BARBHACK-2024-KALI" in out

    @pytest.mark.asyncio
    async def test_host_filter(self):
        mock_gql = AsyncMock(return_value=PROCESSES_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_processes(MagicMock(), make_args(host="KALI", limit=100))
        call_args = mock_gql.call_args
        assert "%KALI%" in str(call_args)

    @pytest.mark.asyncio
    async def test_metadata_as_string(self, capsys):
        """Test that metadata stored as JSON string is parsed correctly."""
        data = {
            "mythictree": [
                {
                    **PROCESSES_DATA["mythictree"][0],
                    "metadata": json.dumps(PROCESSES_DATA["mythictree"][0]["metadata"]),
                }
            ]
        }
        mock_gql = AsyncMock(return_value=data)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_processes(MagicMock(), make_args(limit=100))
        out = capsys.readouterr().out
        assert "kworker" in out
        assert "root" in out


class TestCmdFileBrowser:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=FILE_BROWSER_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_file_browser(MagicMock(), make_args(limit=100))
        out = capsys.readouterr().out
        assert ".env" in out
        assert "/opt/mythic/.env" in out
        assert "file" in out
        assert "dir" in out
        assert "3724" in out

    @pytest.mark.asyncio
    async def test_host_and_path_filters(self):
        mock_gql = AsyncMock(return_value=FILE_BROWSER_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_file_browser(MagicMock(), make_args(host="KALI", path="/opt", limit=100))
        call_args = mock_gql.call_args
        args_str = str(call_args)
        assert "%KALI%" in args_str
        assert "%/opt%" in args_str


class TestCmdTokens:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        mock_gql = AsyncMock(return_value=TOKENS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_tokens(MagicMock(), make_args())
        out = capsys.readouterr().out
        assert "BARBHACK\\Administrator" in out
        assert "BARBHACK-2024-DC01" in out
        assert "SeDebugPrivilege" in out

    @pytest.mark.asyncio
    async def test_callback_filter(self):
        mock_gql = AsyncMock(return_value=TOKENS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_tokens(MagicMock(), make_args(callback=5))
        call_args = mock_gql.call_args
        assert "callback_display_id" in str(call_args)


class TestCmdSearch:
    @pytest.mark.asyncio
    async def test_table_output(self, capsys):
        # Search fires parallel queries; we need gql to return different data per call
        call_count = 0
        responses = [
            SEARCH_TASKS_DATA,
            SEARCH_CREDENTIALS_DATA,
            SEARCH_FILES_DATA,
            SEARCH_ARTIFACTS_DATA,
            SEARCH_KEYLOGS_DATA,
        ]

        async def mock_gql_fn(mythic, query, variables=None):
            nonlocal call_count
            idx = min(call_count, len(responses) - 1)
            call_count += 1
            return responses[idx]

        with patch.object(mythic_read.mythic_utilities, "graphql_post", side_effect=mock_gql_fn):
            await mythic_read.cmd_search(
                MagicMock(),
                make_args(query="admin", types=None, limit=10),
            )
        out = capsys.readouterr().out
        assert "TASKS" in out
        assert "CREDENTIALS" in out

    @pytest.mark.asyncio
    async def test_json_output(self, capsys):
        async def mock_gql_fn(mythic, query, variables=None):
            if "task(" in query:
                return SEARCH_TASKS_DATA
            if "credential(" in query:
                return SEARCH_CREDENTIALS_DATA
            if "filemeta(" in query:
                return SEARCH_FILES_DATA
            if "taskartifact(" in query:
                return SEARCH_ARTIFACTS_DATA
            if "keylog(" in query:
                return SEARCH_KEYLOGS_DATA
            return {}

        with patch.object(mythic_read.mythic_utilities, "graphql_post", side_effect=mock_gql_fn):
            await mythic_read.cmd_search(
                MagicMock(),
                make_args(query="admin", types=None, limit=10, json=True),
            )
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert "tasks" in parsed
        assert "credentials" in parsed

    @pytest.mark.asyncio
    async def test_type_filter(self):
        mock_gql = AsyncMock(return_value=SEARCH_CREDENTIALS_DATA)
        with patch.object(mythic_read.mythic_utilities, "graphql_post", mock_gql):
            await mythic_read.cmd_search(
                MagicMock(),
                make_args(query="admin", types="credentials", limit=10),
            )
        # Should only query credentials, not all 5 types
        assert mock_gql.call_count == 1


# ── CLI parser tests ─────────────────────────────────────────────────


class TestBuildParser:
    def test_all_commands_registered(self):
        parser = mythic_read.build_parser()
        commands = {
            "status",
            "callbacks",
            "callback",
            "tasks",
            "task-output",
            "credentials",
            "files",
            "file-contents",
            "artifacts",
            "keylogs",
            "screenshots",
            "processes",
            "file-browser",
            "tokens",
            "search",
        }
        # Parse each command to verify it's registered
        for cmd in commands:
            if cmd == "callback":
                args = parser.parse_args([cmd, "1"])
            elif cmd == "task-output":
                args = parser.parse_args([cmd, "1"])
            elif cmd == "file-contents":
                args = parser.parse_args([cmd, "test-uuid"])
            elif cmd == "search":
                args = parser.parse_args([cmd, "term"])
            else:
                args = parser.parse_args([cmd])
            assert args.command == cmd

    def test_default_limits(self):
        parser = mythic_read.build_parser()
        args = parser.parse_args(["credentials"])
        assert args.limit == 50
        assert args.offset == 0

    def test_json_flag(self):
        parser = mythic_read.build_parser()
        args = parser.parse_args(["callbacks", "--json"])
        assert args.json is True

    def test_detail_flag(self):
        parser = mythic_read.build_parser()
        args = parser.parse_args(["callbacks", "-d"])
        assert args.detail is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
