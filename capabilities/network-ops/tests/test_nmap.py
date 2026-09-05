import asyncio
import hashlib
import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parent.parent / "tools" / "nmap.py"
SPEC = importlib.util.spec_from_file_location("network_ops_nmap", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
nmap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nmap
SPEC.loader.exec_module(nmap)

OPERATION = {
    "kind": "session_group",
    "id": "de514fec-4c39-4f2e-8601-8d3a547871a6",
    "project_id": "7f62fe86-cc65-48ad-9c53-305f3509016c",
}


@pytest.fixture()
def complete_xml() -> bytes:
    return b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1788523200">
  <scaninfo type="syn" protocol="tcp" numservices="2" services="22,443"/>
  <host starttime="1788523201" endtime="1788523260">
    <status state="up" reason="syn-ack"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames><hostname name="API.Example.COM." type="user"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="closed" reason="reset"/></port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.26" tunnel="ssl" method="probed"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="1788523260" summary="Nmap done" exit="success"/></runstats>
</nmaprun>"""


@pytest.fixture()
def partial_xml() -> bytes:
    return b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1788523200">
  <scaninfo type="udp" protocol="udp" numservices="1" services="53"/>
  <host endtime="1788523210">
    <address addr="2001:0db8::1" addrtype="ipv6"/>
    <ports><port protocol="udp" portid="53"><state state="open|filtered"/></port></ports>
  </host>
  <runstats><finished time="1788523211" summary="Nmap stopped early" exit="error"/></runstats>
</nmaprun>"""


@pytest.fixture()
def failed_xml() -> bytes:
    return b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1788523200">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
  <runstats><finished time="1788523201" summary="Failed to resolve target" exit="error"/></runstats>
</nmaprun>"""


@pytest.fixture()
def duplicate_xml() -> bytes:
    return b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05" start="1788523200">
  <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
  <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
  <host endtime="1788523210">
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <hostnames>
      <hostname name="api.example.com" type="user"/>
      <hostname name="API.EXAMPLE.COM." type="user"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.26" method="probed"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.26" method="probed"/></port>
    </ports>
  </host>
  <runstats><finished time="1788523210" summary="Nmap done" exit="success"/></runstats>
</nmaprun>"""


def _result(xml: bytes, target: str = "API.Example.COM.") -> dict:
    digest = hashlib.sha256(xml).hexdigest()
    return nmap.build_nmap_result(
        xml,
        targets=[target],
        exclusions=[],
        scanner_profile="test-profile",
        operation=OPERATION,
        evidence_locator=f"artifact://nmap-{digest}.xml",
        content_hash=digest,
    )


def test_complete_hostname_scan_preserves_coverage_and_provenance(
    complete_xml: bytes,
) -> None:
    result = _result(complete_xml)

    assert result["item_type"] == "network_recon_result"
    assert result["targets"] == [
        {
            "kind": "hostname",
            "original": "API.Example.COM.",
            "normalized": "api.example.com",
        }
    ]
    assert result["known_address_scope"] == ["203.0.113.10"]
    assert result["transports"] == ["tcp"]
    assert result["ports"] == [{"start": 22, "end": 22}, {"start": 443, "end": 443}]
    assert result["completion_state"] == "completed"
    assert result["endpoints"] == [
        {"ip_address": "203.0.113.10", "transport": "tcp", "port": 22, "state": "closed"},
        {"ip_address": "203.0.113.10", "transport": "tcp", "port": 443, "state": "open"},
    ]
    assert result["dns_results"][0]["query_name"] == "api.example.com"
    assert result["service_fingerprints"][0] == {
        "endpoint": {"ip_address": "203.0.113.10", "transport": "tcp", "port": 443},
        "application_protocol": "ssl/http",
        "product": "nginx",
        "version": "1.26",
        "summary": "http nginx 1.26",
        "method": "nmap-probed",
        "evidence_locator": result["evidence_candidates"][0]["locator"],
    }
    assert result["scanner"] == {"kind": "scanner", "name": "nmap", "version": "7.95"}
    assert result["adapter_input_version"] == "nmap-xml@1"
    assert result["source_contract_version"] == 1
    assert result["evidence_candidates"] == [
        {
            "source_kind": "scan_output",
            "locator": f"artifact://nmap-{hashlib.sha256(complete_xml).hexdigest()}.xml",
            "content_hash": hashlib.sha256(complete_xml).hexdigest(),
            "source_version": "nmap-xml@1.05",
            "media_type": "application/xml",
        }
    ]


def test_cidr_normalization_and_partial_compound_state(partial_xml: bytes) -> None:
    result = _result(partial_xml, target="2001:db8::1234/64")

    assert result["targets"][0] == {
        "kind": "cidr",
        "original": "2001:db8::1234/64",
        "normalized": "2001:db8::/64",
    }
    assert result["completion_state"] == "partial"
    assert result["completion_reason"] == "Nmap stopped early"
    assert result["ip_addresses"] == ["2001:db8::1"]
    assert result["endpoints"] == [
        {
            "ip_address": "2001:db8::1",
            "transport": "udp",
            "port": 53,
            "state": "open|filtered",
        }
    ]


def test_failed_scan_does_not_invent_endpoint_states(failed_xml: bytes) -> None:
    result = _result(failed_xml)

    assert result["completion_state"] == "failed"
    assert result["completion_reason"] == "Failed to resolve target"
    assert result["ip_addresses"] == []
    assert result["endpoints"] == []
    assert result["service_fingerprints"] == []


def test_malformed_xml_is_rejected() -> None:
    with pytest.raises(ValueError, match="Malformed Nmap XML"):
        nmap.parse_nmap_xml(b"<nmaprun>", "artifact://broken.xml")


def test_duplicate_xml_entries_are_deduplicated(duplicate_xml: bytes) -> None:
    result = _result(duplicate_xml)

    assert result["known_address_scope"] == ["203.0.113.10"]
    assert len(result["dns_results"]) == 1
    assert len(result["endpoints"]) == 1
    assert len(result["service_fingerprints"]) == 1
    assert result["ports"] == [{"start": 443, "end": 443}]


def test_scan_logs_exact_content_addressed_xml(complete_xml: bytes, monkeypatch: pytest.MonkeyPatch) -> None:
    logged: dict[str, object] = {}

    async def fake_execute(command: list[str], *, timeout: int) -> str:
        output_path = Path(command[command.index("-oX") + 1])
        output_path.write_bytes(complete_xml)
        logged["command"] = command
        logged["timeout"] = timeout
        return ""

    def fake_log_artifact(path: Path, *, name: str) -> None:
        logged["artifact"] = path.read_bytes()
        logged["name"] = name

    monkeypatch.setattr(nmap, "execute", fake_execute)
    monkeypatch.setattr(nmap, "_operation_reference", lambda: OPERATION)
    monkeypatch.setattr(nmap.dn, "log_artifact", fake_log_artifact)

    result = asyncio.run(
        nmap.Nmap()._scan(
            ["API.Example.COM."],
            ["-F", "--open", "-Pn"],
            scanner_profile="quick-tcp",
        )
    )
    digest = hashlib.sha256(complete_xml).hexdigest()

    assert logged["artifact"] == complete_xml
    assert logged["name"] == f"nmap-{digest}.xml"
    assert logged["command"][-1] == "API.Example.COM."
    assert result["evidence_candidates"][0]["locator"] == f"artifact://nmap-{digest}.xml"


@pytest.mark.parametrize("target", ["localhost", "999.1.1.1", "bad_name.example"])
def test_unsupported_target_identity_is_rejected(target: str) -> None:
    with pytest.raises(ValueError):
        nmap.normalize_target(target)
