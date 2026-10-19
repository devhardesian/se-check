"""se-check.toml: settings and accepted findings."""

from __future__ import annotations

import sys

import pytest

from se_check.audit import apply_acceptances
from se_check.models import Finding, Severity
from se_check.settings import Acceptance, SettingsError, append_acceptance, load_settings

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover
    import tomli as tomllib

KNOWN = {"rls-disabled", "permissive-policy"}


def _write(tmp_path, text: str):
    path = tmp_path / "se-check.toml"
    path.write_text(text)
    return path


def _finding(check="permissive-policy", obj="public.plans", policy="plans are public"):
    return Finding(
        check=check,
        severity=Severity.LOW,
        object=obj,
        title="t",
        detail="d",
        remediation="r",
        evidence={"policy": policy} if policy else {},
    )


def test_full_file(tmp_path):
    settings = load_settings(
        _write(
            tmp_path,
            """
            schemas = ["public", "api"]
            tenant_columns = ["clinic_id"]
            guards = ["is_staff"]

            [[accept]]
            check = "permissive-policy"
            object = "public.plans"
            policy = "plans are public"
            reason = "Shown on the landing page."
            """,
        ),
        KNOWN,
    )
    assert settings.schemas == ("public", "api")
    assert settings.api_roles is None
    assert settings.tenant_columns == ("clinic_id",)
    assert settings.guards == ("is_staff",)
    assert settings.accepted == (
        Acceptance(
            "permissive-policy", "public.plans", "Shown on the landing page.", "plans are public"
        ),
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ('[[accept]]\ncheck = "rls-disabled"\nobject = "public.t"\n', "has no reason"),
        ('[[accept]]\ncheck = "rls-disabled"\nobject = "public.t"\nreason = "  "\n', "no reason"),
        ('[[accept]]\ncheck = "nope"\nobject = "public.t"\nreason = "x"\n', "unknown check"),
        ('[[accept]]\ncheck = "rls-disabled"\nreason = "x"\n', "is missing object"),
        ('[[accept]]\ncheck = "rls-disabled"\nobject = "t"\nreason = "x"\nwhy = "x"\n', "why"),
        ('[[accept]]\ncheck = "rls-disabled"\nobject = 3\nreason = "x"\n', "must be a string"),
        ('accept = "everything"\n', "[[accept]]"),
        ('tennant_columns = ["x"]\n', "unknown setting tennant_columns"),
        ('schemas = "public"\n', "list of names"),
        ("schemas = [\n", "not valid TOML"),
        ('probe = "yes"\n', "[probe] must be a table"),
        ("[probe]\nskip = 1\n", "unknown key skip"),
        ('[probe]\nskip_tables = ["events"]\n', '"schema.table"'),
        ("[probe]\nvalues = 1\n", "[probe.values"),
        ('[probe.values."public.t"]\nwhen = 1979-05-27\n', "a string, a number or a boolean"),
        ('[probe]\nmembership = " "\n', "an SQL statement"),
        ('[probe]\nprivilege_columns = "role"\n', "list column names"),
    ],
)
def test_mistakes_are_explained(tmp_path, text, message):
    with pytest.raises(SettingsError, match=message.replace("[", r"\[")):
        load_settings(_write(tmp_path, text), KNOWN)


def test_append_creates_the_file_and_round_trips_any_text(tmp_path):
    path = tmp_path / "se-check.toml"
    reason = 'Public "pricing" page;\nback\\slash, àccents, tab\t, del\x7f'
    append_acceptance(path, Acceptance("permissive-policy", "public.plans", reason, "p"))
    append_acceptance(path, Acceptance("rls-disabled", "public.audit_log", "Not exposed."))

    data = tomllib.loads(path.read_text())
    assert data["accept"][0]["reason"] == reason
    assert data["accept"][1] == {
        "check": "rls-disabled",
        "object": "public.audit_log",
        "reason": "Not exposed.",
    }
    assert path.read_text().startswith("# se-check settings")


def test_append_keeps_what_is_already_there(tmp_path):
    path = _write(tmp_path, 'schemas = ["public"]  # mine\n')
    append_acceptance(path, Acceptance("rls-disabled", "public.t", "why"))
    assert path.read_text().startswith('schemas = ["public"]  # mine\n')
    assert load_settings(path, KNOWN).schemas == ("public",)


def test_acceptance_matching():
    table_wide = Acceptance("permissive-policy", "public.plans", "why")
    one_policy = Acceptance("permissive-policy", "public.plans", "why", policy="plans are public")
    assert table_wide.matches(_finding(policy="anything"))
    assert one_policy.matches(_finding())
    assert not one_policy.matches(_finding(policy="another policy"))
    assert not table_wide.matches(_finding(obj="public.other"))
    assert not table_wide.matches(_finding(check="rls-disabled"))


def test_apply_acceptances_splits_findings_and_reports_stale_entries():
    plans = Acceptance("permissive-policy", "public.plans", "public pricing")
    stale = Acceptance("permissive-policy", "public.gone", "was public")
    other_check = Acceptance("rls-disabled", "public.gone", "not run this time")
    open_, accepted, unused = apply_acceptances(
        [_finding(), _finding(obj="public.documents")],
        [plans, stale, other_check],
        checks_run=["permissive-policy"],
    )
    assert [f.object for f in open_] == ["public.documents"]
    assert [(a.finding.object, a.reason) for a in accepted] == [("public.plans", "public pricing")]
    assert unused == (stale,)  # rls-disabled didn't run, so its entry can't be judged


def test_probe_settings(tmp_path):
    settings = load_settings(
        _write(
            tmp_path,
            """
[probe]
skip_tables = ["public.events"]
membership = "insert into public.seats values (%(user)s, %(tenant)s)"
claims = { app_metadata = { tenant_id = "{tenant}", roles = ["member"] } }
privilege_columns = ["clearance"]

[probe.values."public.invoices"]
status = "draft"
amount_cents = 100
paid = false
""",
        ),
        KNOWN,
    )
    probe = settings.probe
    assert probe.skip_tables == ("public.events",)
    assert probe.values == {
        "public.invoices": {"status": "draft", "amount_cents": "100", "paid": "false"}
    }
    assert probe.claims == {"app_metadata": {"tenant_id": "{tenant}", "roles": ["member"]}}
    assert probe.membership.startswith("insert into public.seats")
    assert probe.privilege_columns == ("clearance",)


def test_no_probe_section_means_defaults(tmp_path):
    probe = load_settings(_write(tmp_path, 'schemas = ["public"]\n'), KNOWN).probe
    assert probe.skip_tables == () and probe.values == {} and probe.membership is None
