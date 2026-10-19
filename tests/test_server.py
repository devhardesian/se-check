"""The MCP server, exercised in-process through the SDK client."""

from __future__ import annotations

import json

import anyio
from mcp import Client
from test_integration import EXPECTED, EXPECTED_PROBE

from se_check.audit import AuditPlan
from se_check.config import AuditConfig
from se_check.server import build_server
from se_check.settings import Acceptance, SettingsError


def _call(
    dsn: str, tool: str, arguments: dict | None = None, hint: str = "", plan=None, probe=False
):
    async def go():
        server = build_server(dsn, plan or AuditConfig(), hint=hint, probe=probe)
        async with Client(server) as client:
            return await client.call_tool(tool, arguments or {})

    return anyio.run(go)


def test_accepted_findings_reach_the_model_with_their_reason(example_dsn):
    plan = AuditPlan(accepted=(Acceptance("rls-disabled", "public.invoices", "Fake data."),))
    report = _payload(_call(example_dsn, "audit_database", plan=lambda: plan))
    assert "public.invoices" not in {f["object"] for f in report["findings"]}
    assert report["accepted"][0]["reason"] == "Fake data."


def test_broken_settings_are_explained_to_the_model(example_dsn):
    def broken():
        raise SettingsError("se-check.toml: [[accept]] #1 has no reason")

    result = _call(example_dsn, "audit_database", plan=broken)
    assert result.is_error
    assert "has no reason" in result.content[0].text


def _payload(result) -> object:
    if result.structured_content is not None:
        return result.structured_content
    return json.loads(result.content[0].text)


def test_tools_are_listed_as_read_only():
    async def go():
        async with Client(build_server("postgresql://unused", AuditConfig())) as client:
            return await client.list_tools()

    tools = {tool.name: tool for tool in anyio.run(go).tools}
    assert set(tools) == {"audit_database", "list_checks"}
    for tool in tools.values():
        assert tool.annotations.read_only_hint is True
        assert tool.annotations.destructive_hint is False
    # The connection string must never be something the model can choose.
    assert "dsn" not in json.dumps(tools["audit_database"].input_schema)


def test_audit_database(example_dsn):
    result = _call(example_dsn, "audit_database", {"min_severity": "high"})
    assert not result.is_error
    report = _payload(result)
    assert report["summary"]["critical"] == 1
    assert {f["severity"] for f in report["findings"]} <= {"critical", "high"}
    below_high = [e for e in EXPECTED if e[2] not in ("critical", "high")]
    assert report["hidden_below_min_severity"] == len(below_high)
    assert any(f["object"] == "public.invoices" for f in report["findings"])


def test_audit_database_with_selected_checks(example_dsn):
    report = _payload(_call(example_dsn, "audit_database", {"checks": ["user-metadata-auth"]}))
    assert {f["check"] for f in report["findings"]} == {"user-metadata-auth"}


def test_bad_arguments_are_reported_to_the_model(example_dsn):
    result = _call(example_dsn, "audit_database", {"checks": ["nope"]})
    assert result.is_error
    assert "unknown check" in result.content[0].text


def test_connection_failure_is_reported_to_the_model_with_the_hint():
    dsn = "postgresql://nobody@127.0.0.1:1/none?connect_timeout=2"
    result = _call(dsn, "audit_database", hint="Start it with `supabase start`.")
    assert result.is_error
    assert "database error" in result.content[0].text
    assert "supabase start" in result.content[0].text


def test_list_checks():
    result = _call("postgresql://unused", "list_checks")
    checks = _payload(result)
    if isinstance(checks, dict):  # structured output wraps lists in {"result": [...]}
        checks = checks["result"]
    assert "rls-disabled" in {c["id"] for c in checks}


def test_probe_rules_are_not_for_audit_database():
    result = _call("postgresql://unused", "audit_database", {"checks": ["probe-anon-access"]})
    assert result.is_error
    assert "dynamic probe" in result.content[0].text


def _tools(probe: bool):
    async def go():
        async with Client(
            build_server("postgresql://unused", AuditConfig(), probe=probe)
        ) as client:
            return await client.list_tools()

    return {tool.name: tool for tool in anyio.run(go).tools}


def test_probe_tool_only_when_enabled():
    assert "probe_database" not in _tools(probe=False)
    tool = _tools(probe=True)["probe_database"]
    # It writes, inside a transaction it rolls back: honest annotations.
    assert tool.annotations.read_only_hint is False
    assert tool.annotations.destructive_hint is False
    assert "dsn" not in json.dumps(tool.input_schema)


def test_probe_database_adds_the_probe(example_dsn):
    report = _payload(_call(example_dsn, "probe_database", probe=True))
    found = {(f["check"], f["object"], f["severity"]) for f in report["findings"]}
    assert found == EXPECTED | EXPECTED_PROBE
    assert report["probe"]["complete"] is True
    assert report["probe"]["not_reached"] == []


def test_list_checks_names_probe_rules_when_the_probe_is_on():
    def ids(probe):
        payload = _payload(_call("postgresql://unused", "list_checks", probe=probe))
        checks = payload["result"] if isinstance(payload, dict) else payload  # lists get wrapped
        return {check["id"] for check in checks}

    assert "probe-self-escalation" not in ids(False)
    assert "probe-self-escalation" in ids(True)
