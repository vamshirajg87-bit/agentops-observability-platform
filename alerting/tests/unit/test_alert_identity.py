"""
Tests for alerting/alert_identity.py

No database, no network, no environment variables.

The reference digests below were computed independently of the module, by
hashing the literal canonical JSON text shown next to each one.

Coverage:
    1. Canonical encoding: exact bytes, separators, ASCII escaping
    2. Fixed deterministic vectors for every identity
    3. None vs "" and delimiter-bearing strings
    4. Unicode: escaping, no normalization, lone surrogate rejection
    5. Type rejection: bool, float, datetime, bytes, containers
    6. Integer rules
    7. Domain-tag separation and tag validation
    8. Identifier boundaries
    9. Argument validation of the identity functions
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timezone

import pytest

from alert_identity import (
    ATTEMPT_TAG,
    DECISION_TAG,
    DEDUP_TAG,
    canonical_bytes,
    canonical_sha256,
    compute_attempt_id,
    compute_decision_id,
    compute_dedup_key,
    is_sha256_hex,
    validate_identifier,
)

_INV = "a" * 64
_DEC = "b" * 64


# ---------------------------------------------------------------------------
# 1. Canonical encoding
# ---------------------------------------------------------------------------

class TestCanonicalBytes:
    def test_exact_bytes_compact_separators(self):
        assert canonical_bytes("t", "x", 7, None) == b'["t","x",7,null]'

    def test_tag_only(self):
        assert canonical_bytes("t") == b'["t"]'

    def test_output_is_ascii(self):
        canonical_bytes("t", "café ☃ \U0001F600").decode("ascii")

    def test_non_ascii_is_escaped(self):
        assert canonical_bytes("t", "café") == b'["t","caf\\u00e9"]'

    def test_astral_character_is_a_surrogate_pair_escape(self):
        assert canonical_bytes("t", "\U0001F600") == b'["t","\\ud83d\\ude00"]'

    def test_sha256_is_digest_of_canonical_bytes(self):
        expected = hashlib.sha256(canonical_bytes("t", "x", 1)).hexdigest()
        assert canonical_sha256("t", "x", 1) == expected

    def test_digest_is_64_lowercase_hex(self):
        assert is_sha256_hex(canonical_sha256("t", "x"))

    def test_deterministic(self):
        assert canonical_sha256("t", "x", None, 3) == canonical_sha256("t", "x", None, 3)

    def test_value_order_matters(self):
        assert canonical_sha256("t", "a", "b") != canonical_sha256("t", "b", "a")


# ---------------------------------------------------------------------------
# 2. Fixed vectors
# ---------------------------------------------------------------------------

class TestFixedVectors:
    def test_tags(self):
        assert DECISION_TAG == "agentops.alert.decision.v1"
        assert DEDUP_TAG == "agentops.alert.dedup.v1"
        assert ATTEMPT_TAG == "agentops.alert.attempt.v1"

    def test_decision_id(self):
        # ["agentops.alert.decision.v1","aaaa...a","1.0.0"]
        assert compute_decision_id(_INV, "1.0.0") == (
            "37662ef6fd2cbef0870dfd252fb9917de4b54098c0a02be8dd531f7b70f6ba1a"
        )

    def test_dedup_key(self):
        # ["agentops.alert.dedup.v1","latency","agentops-demo-app","agentops.request"]
        assert compute_dedup_key(
            "latency", "agentops-demo-app", "agentops.request",
        ) == "669322b8c0af8c2bc89e3025a1af46552dbc389562105b9e9edfdc5c270ec3ae"

    def test_dedup_key_with_nulls(self):
        # ["agentops.alert.dedup.v1","tool_failure",null,null]
        assert compute_dedup_key("tool_failure", None, None) == (
            "35d5692168e0d6c915380049d4152f2259f6b678d5c5cdd96493c989d5a85d1c"
        )

    def test_dedup_key_with_empty_strings(self):
        # ["agentops.alert.dedup.v1","tool_failure","",""]
        assert compute_dedup_key("tool_failure", "", "") == (
            "014b49845ddc391b77a6cb461362f8253340fb74993aadcd83bd590ba2314213"
        )

    def test_attempt_id(self):
        # ["agentops.alert.attempt.v1","bbbb...b","log",1]
        assert compute_attempt_id(_DEC, "log", 1) == (
            "e70d05bc0423ff172e734b77fbd479151b39d3e2979e809543670dff16f56994"
        )

    def test_unicode_vector(self):
        # ["t","café"]
        assert canonical_sha256("t", "café") == (
            "034fa8cf212e7b8a6aad06151fcffb0f0598f9111013f2f6560ded248d251401"
        )


# ---------------------------------------------------------------------------
# 3. None vs "" and delimiters
# ---------------------------------------------------------------------------

class TestAmbiguity:
    def test_none_differs_from_empty_string(self):
        assert canonical_bytes("t", None) != canonical_bytes("t", "")
        assert compute_dedup_key("x", None, "op") != compute_dedup_key("x", "", "op")
        assert compute_dedup_key("x", "svc", None) != compute_dedup_key("x", "svc", "")

    def test_none_differs_from_the_text_null(self):
        assert canonical_bytes("t", None) != canonical_bytes("t", "null")

    def test_int_differs_from_its_text(self):
        assert canonical_bytes("t", 1) != canonical_bytes("t", "1")

    @pytest.mark.parametrize("left, right", [
        (("ab", "c"), ("a", "bc")),
        (("a|b", "c"), ("a", "b|c")),
        (("a,b", "c"), ("a", "b,c")),
        (('a","b', "c"), ("a", 'b","c')),
        (("a", ""), ("", "a")),
    ])
    def test_field_boundaries_are_unambiguous(self, left, right):
        assert compute_dedup_key("x", *left) != compute_dedup_key("x", *right)

    def test_quote_and_backslash_are_escaped(self):
        assert canonical_bytes("t", 'a"b\\c') == b'["t","a\\"b\\\\c"]'

    def test_control_characters_are_escaped(self):
        assert canonical_bytes("t", "a\nb\tc") == b'["t","a\\nb\\tc"]'

    def test_tool_failure_operation_names_stay_distinct(self):
        first = compute_dedup_key("tool_failure", "svc", "tool.execute/TimeoutError")
        second = compute_dedup_key("tool_failure", "svc", "tool.execute/ValueError")
        assert first != second


# ---------------------------------------------------------------------------
# 4. Unicode
# ---------------------------------------------------------------------------

class TestUnicode:
    def test_no_normalization(self):
        composed = "café"
        decomposed = "café"
        assert unicodedata.normalize("NFC", decomposed) == composed
        assert canonical_sha256("t", composed) != canonical_sha256("t", decomposed)

    def test_case_is_preserved(self):
        assert canonical_sha256("t", "Svc") != canonical_sha256("t", "svc")

    def test_whitespace_is_preserved(self):
        assert canonical_sha256("t", "svc") != canonical_sha256("t", "svc ")

    @pytest.mark.parametrize("bad", ["\ud800", "a\udfffb", "\udc00\ud800"])
    def test_lone_surrogate_in_value_rejected(self, bad):
        with pytest.raises(ValueError, match="surrogate"):
            canonical_bytes("t", bad)

    def test_lone_surrogate_in_tag_rejected(self):
        with pytest.raises(ValueError, match="surrogate"):
            canonical_bytes("t\ud800", "x")

    def test_lone_surrogate_rejected_by_dedup_key(self):
        with pytest.raises(ValueError, match="surrogate"):
            compute_dedup_key("latency", "svc\ud800", "op")

    def test_valid_astral_character_accepted(self):
        assert is_sha256_hex(compute_dedup_key("latency", "svc\U0001F600", "op"))


# ---------------------------------------------------------------------------
# 5. Type rejection
# ---------------------------------------------------------------------------

class TestTypeRejection:
    @pytest.mark.parametrize("bad", [True, False])
    def test_bool_rejected(self, bad):
        with pytest.raises(ValueError, match="bool"):
            canonical_bytes("t", bad)

    @pytest.mark.parametrize("bad", [1.0, 0.5, float("nan"), float("inf")])
    def test_float_rejected(self, bad):
        with pytest.raises(ValueError, match="float"):
            canonical_bytes("t", bad)

    def test_datetime_rejected(self):
        with pytest.raises(ValueError, match="datetime"):
            canonical_bytes("t", datetime(2026, 1, 1, tzinfo=timezone.utc))

    @pytest.mark.parametrize("bad", [b"x", bytearray(b"x")])
    def test_bytes_rejected(self, bad):
        with pytest.raises(ValueError):
            canonical_bytes("t", bad)

    @pytest.mark.parametrize("bad", [["x"], ("x",), {"k": "v"}, {"x"}, object()])
    def test_unsupported_types_rejected(self, bad):
        with pytest.raises(ValueError, match="must be str, int or None"):
            canonical_bytes("t", bad)

    def test_error_names_the_position(self):
        with pytest.raises(ValueError, match="canonical value 2"):
            canonical_bytes("t", "ok", 1.5)

    def test_str_subclass_value_is_hashed_as_its_text(self):
        class Name(str):
            pass

        assert canonical_bytes("t", Name("x")) == canonical_bytes("t", "x")


# ---------------------------------------------------------------------------
# 6. Integers
# ---------------------------------------------------------------------------

class TestIntegers:
    def test_zero_and_positive_accepted(self):
        assert canonical_bytes("t", 0, 12) == b'["t",0,12]'

    def test_negative_rejected(self):
        with pytest.raises(ValueError, match=">= 0"):
            canonical_bytes("t", -1)

    def test_large_integer_is_plain_base_10(self):
        assert canonical_bytes("t", 10**20) == b'["t",100000000000000000000]'


# ---------------------------------------------------------------------------
# 7. Domain tags
# ---------------------------------------------------------------------------

class TestDomainTags:
    def test_same_values_under_different_tags_differ(self):
        assert canonical_sha256("tag.one", "x", "y") != canonical_sha256("tag.two", "x", "y")

    def test_identity_kinds_never_collide_on_equal_values(self):
        values = (_INV, "log")
        assert canonical_sha256(DECISION_TAG, *values) != canonical_sha256(DEDUP_TAG, *values)
        assert canonical_sha256(DECISION_TAG, *values) != canonical_sha256(ATTEMPT_TAG, *values)
        assert canonical_sha256(DEDUP_TAG, *values) != canonical_sha256(ATTEMPT_TAG, *values)

    def test_identity_functions_use_their_tags(self):
        assert compute_decision_id(_INV, "v1") == canonical_sha256(DECISION_TAG, _INV, "v1")
        assert compute_dedup_key("a", "b", None) == canonical_sha256(DEDUP_TAG, "a", "b", None)
        assert compute_attempt_id(_DEC, "log", 2) == canonical_sha256(ATTEMPT_TAG, _DEC, "log", 2)

    @pytest.mark.parametrize("bad", ["", None, 1, b"tag", True])
    def test_tag_must_be_non_empty_str(self, bad):
        with pytest.raises(ValueError, match="tag"):
            canonical_bytes(bad, "x")

    def test_tag_cannot_be_confused_with_a_value(self):
        assert canonical_bytes("a", "b") != canonical_bytes("a,b")


# ---------------------------------------------------------------------------
# 8. Identifiers
# ---------------------------------------------------------------------------

class TestIdentifier:
    @pytest.mark.parametrize("good", [
        "a", "Z", "0", "1.0.0", "local-file", "a_b", "A.b-C_9", "-", ".", "_",
        "x" * 64,
    ])
    def test_valid(self, good):
        assert validate_identifier(good, "name") == good

    @pytest.mark.parametrize("bad", [
        "", "x" * 65, "a b", " a", "a ", "a/b", "a|b", "a:b", "a,b", "a\n",
        "a\t", "café", "a\u0000", "a\ud800",
    ])
    def test_invalid(self, bad):
        with pytest.raises(ValueError, match="name"):
            validate_identifier(bad, "name")

    def test_trailing_newline_rejected(self):
        with pytest.raises(ValueError):
            validate_identifier("1.0.0\n", "policy_version")

    @pytest.mark.parametrize("bad", [None, 1, True, 1.0, b"abc", ["a"]])
    def test_non_str_rejected(self, bad):
        with pytest.raises(ValueError, match="must be str"):
            validate_identifier(bad, "name")


class TestIsSha256Hex:
    def test_valid(self):
        assert is_sha256_hex("0123456789abcdef" * 4)

    @pytest.mark.parametrize("bad", [
        "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\n", "", None, 5,
        b"a" * 64,
    ])
    def test_invalid(self, bad):
        assert not is_sha256_hex(bad)


# ---------------------------------------------------------------------------
# 9. Identity function arguments
# ---------------------------------------------------------------------------

class TestDecisionId:
    def test_changes_with_investigation(self):
        assert compute_decision_id(_INV, "v1") != compute_decision_id("c" * 64, "v1")

    def test_changes_with_policy_version(self):
        assert compute_decision_id(_INV, "v1") != compute_decision_id(_INV, "v2")

    @pytest.mark.parametrize("bad", ["", "abc", "A" * 64, "a" * 63, None, 1])
    def test_investigation_id_must_be_digest(self, bad):
        with pytest.raises(ValueError, match="investigation_id"):
            compute_decision_id(bad, "v1")

    @pytest.mark.parametrize("bad", ["", "v 1", "x" * 65, None, 1])
    def test_policy_version_must_be_identifier(self, bad):
        with pytest.raises(ValueError, match="policy_version"):
            compute_decision_id(_INV, bad)


class TestDedupKey:
    def test_each_dimension_matters(self):
        base = compute_dedup_key("latency", "svc", "op")
        assert base != compute_dedup_key("error_rate", "svc", "op")
        assert base != compute_dedup_key("latency", "svc2", "op")
        assert base != compute_dedup_key("latency", "svc", "op2")

    @pytest.mark.parametrize("bad", ["", None, 1, True])
    def test_anomaly_type_must_be_non_empty_str(self, bad):
        with pytest.raises(ValueError, match="anomaly_type"):
            compute_dedup_key(bad, "svc", "op")

    @pytest.mark.parametrize("bad", [1, True, 1.5, b"svc", ["svc"]])
    def test_service_name_must_be_str_or_none(self, bad):
        with pytest.raises(ValueError, match="service_name"):
            compute_dedup_key("latency", bad, "op")

    @pytest.mark.parametrize("bad", [1, True, 1.5, b"op", ["op"]])
    def test_operation_name_must_be_str_or_none(self, bad):
        with pytest.raises(ValueError, match="operation_name"):
            compute_dedup_key("latency", "svc", bad)


class TestAttemptId:
    def test_each_part_matters(self):
        base = compute_attempt_id(_DEC, "log", 1)
        assert base != compute_attempt_id("c" * 64, "log", 1)
        assert base != compute_attempt_id(_DEC, "file", 1)
        assert base != compute_attempt_id(_DEC, "log", 2)

    def test_attempt_no_one_is_the_minimum(self):
        assert is_sha256_hex(compute_attempt_id(_DEC, "log", 1))

    @pytest.mark.parametrize("bad", [0, -1])
    def test_attempt_no_below_one_rejected(self, bad):
        with pytest.raises(ValueError, match=">= 1"):
            compute_attempt_id(_DEC, "log", bad)

    @pytest.mark.parametrize("bad", [True, 1.0, "1", None])
    def test_attempt_no_must_be_int(self, bad):
        with pytest.raises(ValueError, match="attempt_no must be int"):
            compute_attempt_id(_DEC, "log", bad)

    @pytest.mark.parametrize("bad", ["", "abc", "B" * 64, None])
    def test_decision_id_must_be_digest(self, bad):
        with pytest.raises(ValueError, match="decision_id"):
            compute_attempt_id(bad, "log", 1)

    @pytest.mark.parametrize("bad", ["", "my channel", "x" * 65, None])
    def test_channel_name_must_be_identifier(self, bad):
        with pytest.raises(ValueError, match="channel_name"):
            compute_attempt_id(_DEC, bad, 1)
