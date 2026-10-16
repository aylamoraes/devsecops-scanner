"""Unit tests for secret detection: heuristics, patterns and the analyzer.

All credential-looking values come from ``tests.helpers`` and are built at runtime.
"""

from __future__ import annotations

import pytest

from devsecops_scanner.core.models import Finding, FindingKind, Severity
from devsecops_scanner.secret_detection import SecretAnalyzer
from devsecops_scanner.secret_detection.heuristics import (
    is_placeholder,
    looks_like_non_secret,
    redact,
    shannon_entropy,
)
from devsecops_scanner.secret_detection.patterns import DEFAULT_PATTERNS
from tests.helpers import (
    HIGH_ENTROPY_VALUE,
    fake_aws_key_id,
    fake_aws_secret,
    fake_github_token,
    fake_google_key,
    fake_jwt,
    fake_private_key_header,
    fake_slack_token,
    fake_stripe_key,
    make_source,
)

# The documented AWS example credentials, assembled at runtime.
AWS_EXAMPLE_KEY_ID = "AKIA" + "IOSFODNN7EXAMPLE"
AWS_EXAMPLE_SECRET = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"


def detect(text: str, path: str = "config.txt") -> list[Finding]:
    items = SecretAnalyzer().analyze(make_source(text, path))
    return [item for item in items if isinstance(item, Finding)]


def ids(text: str, path: str = "config.txt") -> list[str]:
    return [finding.rule_id for finding in detect(text, path)]


class TestEntropy:
    def test_empty(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_symbol(self) -> None:
        assert shannon_entropy("aaaaaaaa") == 0.0

    @pytest.mark.parametrize(("value", "bits"), [("ab", 1.0), ("abcd", 2.0), ("abcdefgh", 3.0)])
    def test_uniform_alphabets(self, value: str, bits: float) -> None:
        assert shannon_entropy(value) == pytest.approx(bits)

    def test_random_looking_beats_repetitive(self) -> None:
        assert shannon_entropy(HIGH_ENTROPY_VALUE) > shannon_entropy("abababababababab")


class TestPlaceholders:
    @pytest.mark.parametrize(
        "value",
        [
            "changeme",
            "CHANGE_ME_PLEASE",
            "your_api_key_here",
            "${DB_PASSWORD}",
            "{{ vault.secret }}",
            "<token>",
            "xxxxxxxxxxxx",
            "************",
            "example-value-123",
            "PLACEHOLDER",
            "$(cat secret)",
            "%(password)s",
        ],
    )
    def test_detects_placeholders(self, value: str) -> None:
        assert is_placeholder(value) is True

    @pytest.mark.parametrize("value", [HIGH_ENTROPY_VALUE, "Tr0ub4dor&3xYz", "9f86d081884c7d65"])
    def test_real_looking_values_are_not_placeholders(self, value: str) -> None:
        assert is_placeholder(value) is False


class TestNonSecrets:
    @pytest.mark.parametrize(
        "value",
        [
            "https://example.com/path",
            "/usr/local/bin/tool",
            "./relative/path",
            "../up/one",
            "~/home/file",
            "get_user_token",
            "bert-base-uncased",
            "some.dotted.name",
        ],
    )
    def test_detects_urls_paths_and_identifiers(self, value: str) -> None:
        assert looks_like_non_secret(value) is True

    @pytest.mark.parametrize("value", [HIGH_ENTROPY_VALUE, "Tr0ub4dor&3xYz", "abc123def456"])
    def test_random_values_are_not_flagged(self, value: str) -> None:
        assert looks_like_non_secret(value) is False


class TestRedact:
    def test_short_values_are_fully_masked(self) -> None:
        assert redact("abc") == "***"
        assert redact("a" * 15) == "*" * 12

    def test_long_values_keep_a_four_character_prefix(self) -> None:
        assert redact("AKIA" + "X" * 16) == "AKIA" + "*" * 12

    def test_output_does_not_reveal_the_length(self) -> None:
        assert len(redact("k" * 20)) == len(redact("k" * 80)) == 16

    def test_empty(self) -> None:
        assert redact("") == ""


class TestProviderPatterns:
    @pytest.mark.parametrize(
        ("secret", "rule_id", "severity"),
        [
            (fake_aws_key_id(), "SECRET-AWS-ACCESS-KEY-ID", Severity.HIGH),
            (fake_github_token(), "SECRET-GITHUB-TOKEN", Severity.HIGH),
            (fake_slack_token(), "SECRET-SLACK-TOKEN", Severity.HIGH),
            (fake_google_key(), "SECRET-GOOGLE-API-KEY", Severity.HIGH),
            (fake_stripe_key(), "SECRET-STRIPE-LIVE-KEY", Severity.HIGH),
            (fake_jwt(), "SECRET-JWT", Severity.MEDIUM),
        ],
    )
    def test_detects_provider_secrets(self, secret: str, rule_id: str, severity: Severity) -> None:
        (finding,) = detect(f'value = "{secret}"\n')
        assert finding.rule_id == rule_id
        assert finding.severity is severity
        assert finding.kind is FindingKind.SECRET
        assert finding.cwe == "CWE-798"

    def test_aws_secret_access_key(self) -> None:
        (finding,) = detect(f'aws_secret_access_key = "{fake_aws_secret()}"\n')
        assert finding.rule_id == "SECRET-AWS-SECRET-ACCESS-KEY"
        assert finding.severity is Severity.CRITICAL

    def test_private_key_header(self) -> None:
        (finding,) = detect(f"{fake_private_key_header()}\nMIIE...\n")
        assert finding.rule_id == "SECRET-PRIVATE-KEY"
        assert finding.severity is Severity.CRITICAL
        assert finding.location.line == 1

    @pytest.mark.parametrize("variant", ["EC ", "OPENSSH ", "", "ENCRYPTED "])
    def test_private_key_variants(self, variant: str) -> None:
        header = "-----BEGIN " + variant + "PRIVATE KEY-----"
        assert ids(header + "\n") == ["SECRET-PRIVATE-KEY"]

    def test_provider_match_is_not_reported_twice_as_generic(self) -> None:
        assert ids(f'github_token = "{fake_github_token()}"\n') == ["SECRET-GITHUB-TOKEN"]
        assert ids(f'aws_access_key_id = "{fake_aws_key_id()}"\n') == ["SECRET-AWS-ACCESS-KEY-ID"]

    def test_documented_aws_examples_are_ignored(self) -> None:
        assert ids(f'aws_access_key_id = "{AWS_EXAMPLE_KEY_ID}"\n') == []
        assert ids(f'aws_secret_access_key = "{AWS_EXAMPLE_SECRET}"\n') == []


class TestGenericPatterns:
    def test_hardcoded_credential_assignment(self) -> None:
        assert ids(f'db_password = "{HIGH_ENTROPY_VALUE}"\n') == ["SECRET-GENERIC-CREDENTIAL"]
        assert ids(f"API_KEY: '{HIGH_ENTROPY_VALUE}'\n") == ["SECRET-GENERIC-CREDENTIAL"]
        assert ids(f'{{"auth_token": "{HIGH_ENTROPY_VALUE}"}}\n') == ["SECRET-GENERIC-CREDENTIAL"]

    @pytest.mark.parametrize(
        "line",
        [
            'password = "changeme"',
            'password = "${DB_PASSWORD}"',
            'api_key = "your_api_key_here"',
            'token = "aaaaaaaaaaaa"',
            'secret = "get_user_secret_value"',
            'url_token = "https://example.com/token"',
            'tokenizer = "bert-base-uncased"',
            'password = os.environ["DB_PASSWORD"]',
            'password = ""',
            "password = None",
            'name = "x7Kp2Qm9Vz4Lr8Wd"',  # high entropy, but the key is not credential-like
        ],
    )
    def test_ignores_non_secrets(self, line: str) -> None:
        assert ids(line + "\n") == []

    def test_env_file_assignment(self) -> None:
        assert ids(f"API_KEY={HIGH_ENTROPY_VALUE}\n", ".env") == ["SECRET-ENV-ASSIGNMENT"]
        assert ids(f"export DB_PASSWORD={HIGH_ENTROPY_VALUE}\n", ".env") == [
            "SECRET-ENV-ASSIGNMENT"
        ]

    @pytest.mark.parametrize(
        "line",
        [
            "DB_PASSWORD=",
            "TOKEN=short",
            "API_KEY=changeme-changeme-1",
            "NAME=" + HIGH_ENTROPY_VALUE,
        ],
    )
    def test_env_file_ignores_non_secrets(self, line: str) -> None:
        assert ids(line + "\n", ".env") == []

    def test_connection_string_password(self) -> None:
        text = 'DATABASE_URL = "postgres://admin:s3cr3tPass99@db.internal:5432/app"\n'
        (finding,) = detect(text)
        assert finding.rule_id == "SECRET-CONNECTION-STRING"
        assert finding.snippet is not None
        assert "s3cr3tPass99" not in finding.snippet
        assert "postgres://admin:************@db.internal" in finding.snippet

    @pytest.mark.parametrize(
        "line",
        [
            'url = "postgres://user:${DB_PASSWORD}@db/app"',
            'url = "postgres://user:<password>@db/app"',
            'url = "https://example.org/path"',
            'url = "postgres://db.internal:5432/app"',
        ],
    )
    def test_connection_string_ignores_placeholders_and_credential_free_urls(
        self, line: str
    ) -> None:
        assert ids(line + "\n") == []


class TestNoLeaks:
    """The raw secret must never appear in anything a reporter can print."""

    SECRETS = (
        fake_aws_key_id(),
        fake_github_token(),
        fake_slack_token(),
        fake_google_key(),
        fake_stripe_key(),
        fake_jwt(),
        HIGH_ENTROPY_VALUE,
    )

    @pytest.mark.parametrize("secret", SECRETS)
    def test_secret_value_is_absent_from_the_finding(self, secret: str) -> None:
        findings = detect(f'api_key = "{secret}"\n')
        assert findings, "the fixture should have been detected"
        dumped = "".join(finding.model_dump_json() for finding in findings)
        assert secret not in dumped

    def test_other_secrets_on_the_same_line_are_masked_too(self) -> None:
        key_id, token = fake_aws_key_id(), fake_github_token()
        findings = detect(f'a = "{key_id}"; b = "{token}"\n')
        assert len(findings) == 2
        for finding in findings:
            assert finding.snippet is not None
            assert key_id not in finding.snippet
            assert token not in finding.snippet

    def test_message_never_contains_the_value(self) -> None:
        (finding,) = detect(f'k = "{fake_github_token()}"\n')
        assert "redacted" in finding.message

    def test_match_key_is_a_column_not_a_hash_of_the_secret(self) -> None:
        (finding,) = detect(f'k = "{fake_github_token()}"\n')
        assert finding.match_key == "6"
        assert finding.location.column == 6


class TestAnalyzer:
    def test_reports_line_and_column(self) -> None:
        text = f'first = 1\nsecond = "{fake_github_token()}"\n'
        (finding,) = detect(text)
        assert finding.location.line == 2
        assert finding.location.column == 11

    def test_same_secret_twice_is_reported_twice(self) -> None:
        token = fake_github_token()
        findings = detect(f'a = "{token}"\nb = "{token}"\n')
        assert [f.location.line for f in findings] == [1, 2]
        assert len({f.fingerprint() for f in findings}) == 2

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("src/app.py", True),
            (".env", True),
            ("config/settings.yaml", True),
            ("README.md", True),
            ("logo.svg", False),
            ("bundle.min.js", False),
            ("bundle.js.map", False),
            ("styles.MIN.CSS", False),
        ],
    )
    def test_accepts(self, path: str, expected: bool) -> None:
        assert SecretAnalyzer().accepts(path) is expected

    def test_short_lines_are_skipped(self) -> None:
        assert detect("a=1\n") == []

    def test_remediation_mentions_rotation(self) -> None:
        (finding,) = detect(f'k = "{fake_github_token()}"\n')
        assert finding.remediation is not None
        assert "rotate" in finding.remediation.lower()

    def test_very_long_lines_do_not_hang(self) -> None:
        # Bounded quantifiers: a hostile line must not trigger catastrophic backtracking.
        hostile = "password=" + "a" * 200_000 + "\n" + "token = '" + "b" * 200_000
        assert detect(hostile) == []

    def test_snippet_is_truncated(self) -> None:
        padded = "x" * 300 + f' = "{fake_github_token()}"'
        (finding,) = detect(padded + "\n")
        assert finding.snippet is not None
        assert len(finding.snippet) <= 160


class TestCatalogue:
    def test_rule_ids_are_unique(self) -> None:
        ids_ = [pattern.rule_id for pattern in DEFAULT_PATTERNS]
        assert len(ids_) == len(set(ids_))
        assert all(i.startswith("SECRET-") for i in ids_)

    def test_specific_patterns_come_before_generic_ones(self) -> None:
        ordered = [pattern.rule_id for pattern in DEFAULT_PATTERNS]
        assert ordered.index("SECRET-GITHUB-TOKEN") < ordered.index("SECRET-GENERIC-CREDENTIAL")
        assert ordered.index("SECRET-AWS-ACCESS-KEY-ID") < ordered.index(
            "SECRET-GENERIC-CREDENTIAL"
        )

    def test_rules_listing(self) -> None:
        rules = SecretAnalyzer().rules()
        assert len(rules) == len(DEFAULT_PATTERNS)
        assert all(rule.kind is FindingKind.SECRET and rule.cwe == "CWE-798" for rule in rules)
