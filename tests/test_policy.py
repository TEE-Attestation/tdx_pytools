# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Tests for tdx_pytools.policy: AttestationPolicy loading, rule evaluation,
# nested-field handling, TCB rules and the validate_quote_with_policy helper.
#
# The fixture is Intel's sample TDX v4 quote from the DCAP Quote Verification
# Library (see tests/data/README.md). It is a structural sample: every TD
# measurement (mr_td, rtmr0-3, ...) is zero, while tee_tcb_svn and the QE
# vendor id are non-zero. Values asserted below are read from it in
# ``_fixture_values``.

import json
from pathlib import Path

import pytest

from tdx_pytools import (
    AttestationPolicy,
    PolicyValidationError,
    Quote,
    Tcb,
    TcbStatus,
    validate_quote_with_policy,
)

QUOTE_PATH = Path(__file__).parent / "data" / "intel_tdx_sample" / "quote.dat"

# Byte-field values carried by the fixture quote, as lowercase hex.
MR_TD_HEX = "00" * 48
RTMR0_HEX = "00" * 48
TEE_TCB_SVN_HEX = "52c1a38cf7edf30a524b4ebb049f59c7"
QE_VENDOR_ID_HEX = "939a7233f79c4ca9940a0db3957f0607"  # Intel SGX QE
CPU_SVN_HEX = "52c1a38cf7edf30a524b4ebb049f59c7"
OTHER_48_HEX = "ab" * 48
OTHER_16_HEX = "ab" * 16


@pytest.fixture(scope="module")
def quote() -> Quote:
    return Quote.unpack(QUOTE_PATH.read_bytes())


@pytest.fixture(autouse=True, scope="module")
def _fixture_values(quote):
    """Pin the fixture values the tests below rely on; update if the file changes."""
    assert quote.header.version == 4
    assert quote.header.tee_type == 0x81
    assert quote.body.mr_td.hex() == MR_TD_HEX
    assert quote.body.rtmr0.hex() == RTMR0_HEX
    assert quote.body.tee_tcb_svn.hex() == TEE_TCB_SVN_HEX
    assert quote.header.qe_vendor_id.hex() == QE_VENDOR_ID_HEX
    assert quote.signature_data.qe_cert_data.qe_report.cpu_svn.hex() == CPU_SVN_HEX


@pytest.fixture
def tcb_all_up_to_date():
    return {
        "update": "standard",
        "platform_tcb": Tcb(status=TcbStatus.UP_TO_DATE),
        "tdx_module_tcb": Tcb(status=TcbStatus.UP_TO_DATE),
        "qe_tcb": Tcb(status=TcbStatus.UP_TO_DATE),
    }


def _policy(rules: dict, **metadata) -> AttestationPolicy:
    return AttestationPolicy(
        policy_data={
            "metadata": {"name": "test policy", **metadata},
            "validation_rules": rules,
        }
    )


def _passes(quote, rules: dict, tcb=None) -> bool:
    return _policy(rules).validate_quote(quote, tcb or {}) is True


def _fails_on(quote, rules: dict, *fields: str, tcb=None):
    """Assert validation fails and every named field appears in the error."""
    with pytest.raises(PolicyValidationError) as exc:
        _policy(rules).validate_quote(quote, tcb or {})
    message = str(exc.value)
    for field in fields:
        assert field in message, f"{field!r} not in {message!r}"
    return message


# ── Construction and loading ─────────────────────────────────────────────────


class TestConstruction:
    def test_requires_data_or_file(self):
        with pytest.raises(ValueError, match="Either policy_data or policy_file"):
            AttestationPolicy()

    def test_from_data(self):
        assert _policy({}).policy["metadata"]["name"] == "test policy"

    def test_from_file(self, tmp_path):
        path = tmp_path / "p.json"
        path.write_text(
            json.dumps(
                {
                    "metadata": {"name": "f"},
                    "validation_rules": {"header": {"version": {"exact_match": 4}}},
                }
            )
        )
        assert (
            AttestationPolicy(policy_file=str(path)).policy["metadata"]["name"] == "f"
        )

    def test_missing_file(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="Policy file not found"):
            AttestationPolicy(policy_file=str(tmp_path / "nope.json"))

    def test_invalid_json_file(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(json.JSONDecodeError):
            AttestationPolicy(policy_file=str(path))

    @pytest.mark.parametrize("missing", ["metadata", "validation_rules"])
    def test_required_sections(self, missing):
        data = {"metadata": {}, "validation_rules": {}}
        del data[missing]
        with pytest.raises(ValueError, match=f"missing required section: {missing}"):
            AttestationPolicy(policy_data=data)

    def test_empty_rules_pass(self, quote):
        assert _passes(quote, {})

    def test_summary_mentions_metadata_and_rules(self):
        policy = _policy(
            {"body": {"mr_td": {"exact_match": MR_TD_HEX}}},
            version="9.9",
            description="desc",
        )
        summary = policy.get_policy_summary()
        assert "test policy" in summary
        assert "9.9" in summary
        assert "desc" in summary
        assert "mr_td" in summary


# ── exact_match ──────────────────────────────────────────────────────────────


class TestExactMatch:
    def test_integer_pass(self, quote):
        assert _passes(quote, {"header": {"version": {"exact_match": 4}}})

    def test_integer_fail(self, quote):
        _fails_on(quote, {"header": {"version": {"exact_match": 5}}}, "header.version")

    def test_bare_value_is_exact_match_nested(self, quote):
        assert _passes(quote, {"header": {"version": 4}})
        _fails_on(quote, {"header": {"version": 5}}, "header.version")

    def test_bare_value_is_exact_match_top_level(self, quote):
        """Top-level fields on Quote are objects, so a bare scalar can never
        match; the rule must still be evaluated (and fail) rather than raise.

        Regression test: top-level bare values were once passed straight to
        _validate_object (which expects a dict) and reported via the broad
        except handler instead of the rule itself.
        """
        _fails_on(quote, {"signature_len": 0}, "signature_len")
        assert _passes(quote, {"signature_len": quote.signature_len})

    def test_bytes_pass(self, quote):
        assert _passes(quote, {"body": {"mr_td": {"exact_match": MR_TD_HEX}}})

    def test_bytes_fail(self, quote):
        _fails_on(
            quote, {"body": {"mr_td": {"exact_match": OTHER_48_HEX}}}, "body.mr_td"
        )

    def test_bytes_non_zero_value(self, quote):
        assert _passes(
            quote, {"body": {"tee_tcb_svn": {"exact_match": TEE_TCB_SVN_HEX}}}
        )
        _fails_on(
            quote,
            {"body": {"tee_tcb_svn": {"exact_match": OTHER_16_HEX}}},
            "body.tee_tcb_svn",
        )

    @pytest.mark.parametrize(
        "variant",
        [MR_TD_HEX.upper(), "0x" + MR_TD_HEX, "0x" + MR_TD_HEX.upper()],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_bytes_hex_normalisation(self, quote, variant):
        assert _passes(quote, {"body": {"mr_td": {"exact_match": variant}}})

    def test_bytes_bare_value_shorthand(self, quote):
        assert _passes(quote, {"body": {"mr_td": MR_TD_HEX}})
        _fails_on(quote, {"body": {"mr_td": OTHER_48_HEX}}, "body.mr_td")

    def test_bytes_wrong_length_hex_fails(self, quote):
        _fails_on(quote, {"body": {"mr_td": {"exact_match": "aabb"}}}, "body.mr_td")

    def test_bytes_invalid_hex_fails_not_raises(self, quote):
        _fails_on(quote, {"body": {"mr_td": {"exact_match": "zz" * 48}}}, "body.mr_td")

    def test_bytes_against_bytes_value(self, quote):
        assert _passes(quote, {"body": {"mr_td": {"exact_match": quote.body.mr_td}}})
        _fails_on(
            quote, {"body": {"mr_td": {"exact_match": b"\xab" * 48}}}, "body.mr_td"
        )

    def test_deeply_nested_bytes(self, quote):
        rules = {
            "signature_data": {
                "qe_cert_data": {"qe_report": {"cpu_svn": {"exact_match": CPU_SVN_HEX}}}
            }
        }
        assert _passes(quote, rules)
        rules["signature_data"]["qe_cert_data"]["qe_report"]["cpu_svn"][
            "exact_match"
        ] = ("00" * 16)
        _fails_on(quote, rules, "signature_data.qe_cert_data.qe_report.cpu_svn")


# ── min_value / max_value ────────────────────────────────────────────────────


class TestRangeRules:
    @pytest.mark.parametrize("bound", [0, 4])
    def test_min_pass(self, quote, bound):
        assert _passes(quote, {"header": {"version": {"min_value": bound}}})

    def test_min_fail(self, quote):
        _fails_on(quote, {"header": {"version": {"min_value": 5}}}, "header.version")

    @pytest.mark.parametrize("bound", [4, 99])
    def test_max_pass(self, quote, bound):
        assert _passes(quote, {"header": {"version": {"max_value": bound}}})

    def test_max_fail(self, quote):
        _fails_on(quote, {"header": {"version": {"max_value": 3}}}, "header.version")

    def test_min_and_max_together(self, quote):
        assert _passes(quote, {"header": {"version": {"min_value": 4, "max_value": 4}}})
        _fails_on(
            quote,
            {"header": {"version": {"min_value": 4, "max_value": 3}}},
            "header.version",
        )


# ── boolean ──────────────────────────────────────────────────────────────────


class TestBoolean:
    """The Quote has no bool attributes, so exercise the validator through
    comparison with an int field, pinning the routing behaviour."""

    def test_explicit_boolean_rule_against_int(self, quote):
        # version == 4; 4 != True, so this must fail via the boolean validator.
        _fails_on(quote, {"header": {"version": {"boolean": True}}}, "header.version")

    def test_bare_bool_routes_to_boolean(self, quote):
        _fails_on(quote, {"header": {"version": True}}, "header.version")


# ── allow_list / deny_list on scalar fields ──────────────────────────────────


class TestScalarLists:
    def test_allow_pass(self, quote):
        assert _passes(quote, {"header": {"version": {"allow_list": [4, 5]}}})

    def test_allow_fail(self, quote):
        _fails_on(
            quote, {"header": {"version": {"allow_list": [5, 6]}}}, "header.version"
        )

    def test_allow_empty_fails(self, quote):
        _fails_on(quote, {"header": {"version": {"allow_list": []}}}, "header.version")

    def test_deny_pass(self, quote):
        assert _passes(quote, {"header": {"version": {"deny_list": [5, 6]}}})

    def test_deny_fail(self, quote):
        _fails_on(quote, {"header": {"version": {"deny_list": [4]}}}, "header.version")

    def test_deny_empty_passes(self, quote):
        assert _passes(quote, {"header": {"version": {"deny_list": []}}})


# ── allow_list / deny_list on byte fields ────────────────────────────────────


class TestByteFieldLists:
    """Hex entries in a list must be compared the same way exact_match compares
    a hex string: normalised and decoded to bytes before the membership test.

    Regression tests: the lists were once compared without decoding, so for
    byte fields an allow_list rejected every value and a deny_list allowed
    every value.
    """

    def test_allow_accepts_listed(self, quote):
        assert _passes(
            quote, {"body": {"mr_td": {"allow_list": [OTHER_48_HEX, MR_TD_HEX]}}}
        )

    def test_allow_rejects_unlisted(self, quote):
        _fails_on(
            quote, {"body": {"mr_td": {"allow_list": [OTHER_48_HEX]}}}, "body.mr_td"
        )

    def test_allow_empty_fails(self, quote):
        _fails_on(quote, {"body": {"mr_td": {"allow_list": []}}}, "body.mr_td")

    @pytest.mark.parametrize(
        "variant",
        [MR_TD_HEX.upper(), "0x" + MR_TD_HEX, "0x" + MR_TD_HEX.upper()],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_allow_hex_normalisation(self, quote, variant):
        assert _passes(quote, {"body": {"mr_td": {"allow_list": [variant]}}})

    def test_deny_rejects_listed(self, quote):
        _fails_on(
            quote,
            {"body": {"mr_td": {"deny_list": [OTHER_48_HEX, MR_TD_HEX]}}},
            "body.mr_td",
        )

    def test_deny_accepts_unlisted(self, quote):
        assert _passes(quote, {"body": {"mr_td": {"deny_list": [OTHER_48_HEX]}}})

    def test_deny_empty_passes(self, quote):
        assert _passes(quote, {"body": {"mr_td": {"deny_list": []}}})

    @pytest.mark.parametrize(
        "variant",
        [MR_TD_HEX.upper(), "0x" + MR_TD_HEX, "0x" + MR_TD_HEX.upper()],
        ids=["upper", "0x", "0x-upper"],
    )
    def test_deny_hex_normalisation(self, quote, variant):
        _fails_on(quote, {"body": {"mr_td": {"deny_list": [variant]}}}, "body.mr_td")

    def test_lists_accept_bytes_entries(self, quote):
        assert _passes(quote, {"body": {"mr_td": {"allow_list": [quote.body.mr_td]}}})
        _fails_on(
            quote, {"body": {"mr_td": {"deny_list": [quote.body.mr_td]}}}, "body.mr_td"
        )

    def test_invalid_hex_entry_fails_not_raises(self, quote):
        _fails_on(quote, {"body": {"mr_td": {"allow_list": ["zz" * 48]}}}, "body.mr_td")
        _fails_on(quote, {"body": {"mr_td": {"deny_list": ["zz" * 48]}}}, "body.mr_td")

    def test_other_byte_fields(self, quote):
        assert _passes(quote, {"body": {"rtmr0": {"allow_list": [RTMR0_HEX]}}})
        _fails_on(quote, {"body": {"rtmr0": {"deny_list": [RTMR0_HEX]}}}, "body.rtmr0")

    def test_non_zero_byte_fields(self, quote):
        """Match on fields whose fixture values are non-zero, so a trivially
        all-zero comparison cannot mask a decoding error."""
        assert _passes(
            quote, {"body": {"tee_tcb_svn": {"allow_list": [TEE_TCB_SVN_HEX]}}}
        )
        _fails_on(
            quote,
            {"body": {"tee_tcb_svn": {"allow_list": [OTHER_16_HEX]}}},
            "body.tee_tcb_svn",
        )
        _fails_on(
            quote,
            {"body": {"tee_tcb_svn": {"deny_list": [TEE_TCB_SVN_HEX]}}},
            "body.tee_tcb_svn",
        )
        assert _passes(
            quote,
            {
                "header": {
                    "qe_vendor_id": {"allow_list": [OTHER_16_HEX, QE_VENDOR_ID_HEX]}
                }
            },
        )
        _fails_on(
            quote,
            {"header": {"qe_vendor_id": {"deny_list": [QE_VENDOR_ID_HEX.upper()]}}},
            "header.qe_vendor_id",
        )

    def test_single_entry_allow_list_agrees_with_exact_match(self, quote):
        for hex_value, expected in ((MR_TD_HEX, True), (OTHER_48_HEX, False)):
            exact = {"body": {"mr_td": {"exact_match": hex_value}}}
            allow = {"body": {"mr_td": {"allow_list": [hex_value]}}}
            if expected:
                assert _passes(quote, exact) and _passes(quote, allow)
            else:
                _fails_on(quote, exact, "body.mr_td")
                _fails_on(quote, allow, "body.mr_td")


# ── Nested fields and error reporting ────────────────────────────────────────


class TestNestedFields:
    def test_multiple_rtmrs(self, quote):
        assert _passes(
            quote,
            {
                "body": {
                    "mr_td": {"exact_match": MR_TD_HEX},
                    "rtmr0": {"exact_match": RTMR0_HEX},
                    "rtmr1": {"exact_match": quote.body.rtmr1.hex()},
                }
            },
        )

    def test_unknown_top_level_field_fails(self, quote):
        _fails_on(quote, {"not_a_field": {"exact_match": 1}}, "not_a_field")

    def test_unknown_nested_field_fails(self, quote):
        _fails_on(
            quote, {"body": {"not_a_field": {"exact_match": 1}}}, "body.not_a_field"
        )

    def test_all_failures_reported_together(self, quote):
        message = _fails_on(
            quote,
            {
                "header": {"version": {"exact_match": 9}},
                "body": {
                    "mr_td": {"exact_match": OTHER_48_HEX},
                    "rtmr0": {"deny_list": [RTMR0_HEX]},
                },
            },
            "header.version",
            "body.mr_td",
            "body.rtmr0",
        )
        assert message.count(",") >= 2

    def test_passing_rules_are_not_reported(self, quote):
        message = _fails_on(
            quote,
            {
                "body": {
                    "mr_td": {"exact_match": MR_TD_HEX},
                    "rtmr0": {"exact_match": OTHER_48_HEX},
                }
            },
            "body.rtmr0",
        )
        assert "mr_td" not in message


# ── TCB rules ────────────────────────────────────────────────────────────────


class TestTcbRules:
    def test_all_up_to_date_passes(self, quote, tcb_all_up_to_date):
        rules = {
            "tcb": {
                "update": "standard",
                "platform_tcb": "UpToDate",
                "tdx_module_tcb": "UpToDate",
                "qe_tcb": "UpToDate",
            }
        }
        assert _passes(quote, rules, tcb=tcb_all_up_to_date)

    def test_better_than_required_passes(self, quote, tcb_all_up_to_date):
        rules = {"tcb": {"platform_tcb": "OutOfDate"}}
        assert _passes(quote, rules, tcb=tcb_all_up_to_date)

    def test_worse_than_required_fails(self, quote, tcb_all_up_to_date):
        tcb_all_up_to_date["platform_tcb"] = Tcb(status=TcbStatus.OUT_OF_DATE)
        rules = {"tcb": {"platform_tcb": "UpToDate"}}
        with pytest.raises(PolicyValidationError, match="platform_tcb"):
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)

    def test_revoked_fails_against_any_requirement(self, quote, tcb_all_up_to_date):
        tcb_all_up_to_date["qe_tcb"] = Tcb(status=TcbStatus.REVOKED)
        rules = {"tcb": {"qe_tcb": "OutOfDateConfigurationNeeded"}}
        with pytest.raises(PolicyValidationError, match="qe_tcb"):
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)

    def test_unknown_component_fails(self, quote, tcb_all_up_to_date):
        rules = {"tcb": {"not_a_component": "UpToDate"}}
        with pytest.raises(PolicyValidationError, match="not_a_component"):
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)

    def test_invalid_status_string_fails(self, quote, tcb_all_up_to_date):
        rules = {"tcb": {"platform_tcb": "NotARealStatus"}}
        with pytest.raises(PolicyValidationError, match="NotARealStatus"):
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)

    def test_update_early_required_but_standard_given_fails(
        self, quote, tcb_all_up_to_date
    ):
        rules = {"tcb": {"update": "early"}}
        with pytest.raises(PolicyValidationError, match="early"):
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)

    def test_update_early_satisfied(self, quote, tcb_all_up_to_date):
        tcb_all_up_to_date["update"] = "early"
        assert _passes(quote, {"tcb": {"update": "early"}}, tcb=tcb_all_up_to_date)

    def test_update_standard_accepts_early(self, quote, tcb_all_up_to_date):
        tcb_all_up_to_date["update"] = "early"
        assert _passes(quote, {"tcb": {"update": "standard"}}, tcb=tcb_all_up_to_date)

    def test_all_component_failures_reported(self, quote, tcb_all_up_to_date):
        tcb_all_up_to_date["platform_tcb"] = Tcb(status=TcbStatus.OUT_OF_DATE)
        tcb_all_up_to_date["qe_tcb"] = Tcb(status=TcbStatus.OUT_OF_DATE)
        rules = {"tcb": {"platform_tcb": "UpToDate", "qe_tcb": "UpToDate"}}
        with pytest.raises(PolicyValidationError) as exc:
            _policy(rules).validate_quote(quote, tcb_all_up_to_date)
        assert "platform_tcb" in str(exc.value) and "qe_tcb" in str(exc.value)

    def test_tcb_and_body_rules_together(self, quote, tcb_all_up_to_date):
        rules = {
            "tcb": {"platform_tcb": "UpToDate"},
            "body": {"mr_td": {"exact_match": MR_TD_HEX}},
        }
        assert _passes(quote, rules, tcb=tcb_all_up_to_date)

    def test_policy_is_reusable_across_validations(self, quote, tcb_all_up_to_date):
        """validate_quote must not mutate the policy; a second call must apply
        the same TCB rules as the first.

        Regression test: the TCB rules were popped out of self.policy during
        validation, so a reused AttestationPolicy silently skipped them.
        """
        policy = _policy(
            {"tcb": {"update": "early", "platform_tcb": "UpToDate"}},
            name="reused",
        )
        # First call: standard < early, so this must fail.
        with pytest.raises(PolicyValidationError, match="early"):
            policy.validate_quote(quote, tcb_all_up_to_date)
        # Second call with the same inputs must fail identically.
        with pytest.raises(PolicyValidationError, match="early"):
            policy.validate_quote(quote, tcb_all_up_to_date)
        # And the policy document is untouched.
        assert policy.policy["validation_rules"]["tcb"] == {
            "update": "early",
            "platform_tcb": "UpToDate",
        }

    def test_policy_data_dict_not_mutated(self, quote, tcb_all_up_to_date):
        """The caller's dict must not be modified either."""
        data = {
            "metadata": {"name": "caller"},
            "validation_rules": {"tcb": {"platform_tcb": "UpToDate"}},
        }
        snapshot = json.loads(json.dumps(data))
        AttestationPolicy(policy_data=data).validate_quote(quote, tcb_all_up_to_date)
        assert data == snapshot


# ── report_data binding ──────────────────────────────────────────────────────


class TestReportData:
    def test_matching_bytes(self, quote):
        assert _policy({}).validate_quote(quote, {}, report_data=quote.body.report_data)

    def test_matching_hex(self, quote):
        hex_value = quote.body.report_data.hex()
        assert _policy({}).validate_quote(quote, {}, report_data=hex_value)
        assert _policy({}).validate_quote(
            quote, {}, report_data="0x" + hex_value.upper()
        )

    def test_mismatch_bytes(self, quote):
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({}).validate_quote(quote, {}, report_data=b"\xab" * 64)

    def test_mismatch_hex(self, quote):
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({}).validate_quote(quote, {}, report_data="ab" * 64)

    def test_invalid_hex(self, quote):
        with pytest.raises(PolicyValidationError, match="Invalid hex string"):
            _policy({}).validate_quote(quote, {}, report_data="zz" * 64)

    def test_report_data_checked_before_rules(self, quote):
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            _policy({"header": {"version": 9}}).validate_quote(
                quote, {}, report_data=b"\xab" * 64
            )

    def test_none_skips_check(self, quote):
        assert _policy({}).validate_quote(quote, {}, report_data=None)


# ── validate_quote_with_policy helper ────────────────────────────────────────


class TestHelper:
    def _write(self, tmp_path, rules):
        path = tmp_path / "policy.json"
        path.write_text(
            json.dumps({"metadata": {"name": "h"}, "validation_rules": rules})
        )
        return str(path)

    def test_pass(self, quote, tmp_path):
        path = self._write(tmp_path, {"header": {"version": {"exact_match": 4}}})
        assert validate_quote_with_policy(quote, {}, path)

    def test_fail(self, quote, tmp_path):
        path = self._write(tmp_path, {"header": {"version": {"exact_match": 9}}})
        with pytest.raises(PolicyValidationError):
            validate_quote_with_policy(quote, {}, path)

    def test_report_data_forwarded(self, quote, tmp_path):
        path = self._write(tmp_path, {})
        assert validate_quote_with_policy(
            quote, {}, path, report_data=quote.body.report_data
        )
        with pytest.raises(PolicyValidationError, match="Report data mismatch"):
            validate_quote_with_policy(quote, {}, path, report_data=b"\xab" * 64)


# ── Example policy shipped in the repo ───────────────────────────────────────


class TestExamplePolicy:
    EXAMPLE = Path(__file__).parent.parent / "example_policy.json"

    def test_loads(self):
        assert (
            "validation_rules"
            in AttestationPolicy(policy_file=str(self.EXAMPLE)).policy
        )

    def test_evaluates_without_error(self, quote, tcb_all_up_to_date):
        policy = AttestationPolicy(policy_file=str(self.EXAMPLE))
        try:
            policy.validate_quote(quote, tcb_all_up_to_date)
        except PolicyValidationError:
            # The example pins values for a different machine; failing is fine,
            # raising anything else is not.
            pass
