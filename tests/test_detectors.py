from credscan.detectors import (
    CONTENT_RULES,
    HIGH_ENTROPY_RULE,
    LINE_RULES,
    matches_known_secret_shape,
)
from credscan.entropy import is_high_entropy_secret

_RULES_BY_ID = {rule.rule_id: rule for rule in LINE_RULES}


def _matches(rule_id: str, line: str) -> list[str]:
    return [text for _, _, text in _RULES_BY_ID[rule_id].finditer(line)]


def test_aws_access_key_id_matches_the_documented_aws_example_key():
    line = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    assert _matches("aws-access-key-id", line) == ["AKIAIOSFODNN7EXAMPLE"]


def test_aws_access_key_id_ignores_short_lookalikes():
    assert _matches("aws-access-key-id", "AKIA_TOO_SHORT") == []


def test_aws_secret_access_key_requires_the_context_keyword():
    line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    assert _matches("aws-secret-access-key", line) == ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]


def test_aws_secret_access_key_ignores_a_bare_40_char_string_without_context():
    line = "just_some_value = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert _matches("aws-secret-access-key", line) == []


def test_private_key_pem_matches_common_headers():
    assert _matches("private-key-pem", "-----BEGIN RSA PRIVATE KEY-----") != []
    assert _matches("private-key-pem", "-----BEGIN OPENSSH PRIVATE KEY-----") != []
    assert _matches("private-key-pem", "-----BEGIN PRIVATE KEY-----") != []


def test_private_key_pem_ignores_public_keys():
    assert _matches("private-key-pem", "-----BEGIN PUBLIC KEY-----") == []


def test_jwt_matches_the_canonical_jwt_io_example():
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    assert _matches("jwt", f"Authorization: Bearer {token}") == [token]


def test_jwt_ignores_a_two_segment_string():
    assert _matches("jwt", "eyJhbGciOiJIUzI1NiJ9.notathirdsegment") == []


def test_github_token_matches_the_classic_pat_prefix():
    token = "ghp_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a"
    assert _matches("github-token", f"GITHUB_TOKEN={token}") == [token]


def test_github_token_matches_every_documented_prefix():
    for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
        token = prefix + "a" * 36
        assert _matches("github-token", token) == [token]


def test_github_token_matches_the_fine_grained_pat_prefix():
    token = "github_pat_" + "a" * 22
    assert _matches("github-token", token) == [token]


def test_github_token_ignores_a_bare_hex_string_without_the_prefix():
    assert _matches("github-token", "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a") == []


def test_github_token_entropy_alone_would_not_have_caught_this_shape():
    # The whole reason this rule exists: a real ghp_ token's near-hex alphabet routinely lands
    # under the generic entropy threshold, so without this shape rule it goes undetected.
    token = "ghp_9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a"
    assert is_high_entropy_secret(token) is False
    assert matches_known_secret_shape(token) is True


def test_bearer_token_matches_and_excludes_the_bearer_keyword():
    # Deliberately not shaped like a real vendor prefix (e.g. Stripe's sk_live_) -- the rule
    # itself is generic, and a vendor-shaped fixture would trip GitHub push protection even
    # though it's fake, since only AWS/GitHub publish an official "this is a safe example" key.
    matches = _matches("bearer-token", "Authorization: Bearer tok_notarealtoken1234567890abcdef")
    assert matches == ["tok_notarealtoken1234567890abcdef"]


def test_generic_api_key_assignment_matches_common_key_names():
    assert _matches("generic-api-key-assignment", 'API_KEY="abcd1234efgh5678ijkl"') != []
    assert _matches("generic-api-key-assignment", "client_secret: abcd1234efgh5678ijkl") != []


def test_generic_api_key_assignment_ignores_short_values():
    assert _matches("generic-api-key-assignment", 'API_KEY="short"') == []


def test_gcp_service_account_rule_requires_both_fields_present():
    rule = CONTENT_RULES[0]
    content = (
        '{\n  "type": "service_account",\n  "private_key": "-----BEGIN PRIVATE KEY-----..."\n}'
    )
    results = list(rule.find(content))
    assert len(results) == 1
    offset, matched = results[0]
    assert matched == "private_key"
    assert content.count("\n", 0, offset) + 1 == 3  # the private_key field is on line 3


def test_gcp_service_account_rule_ignores_json_without_the_type_marker():
    rule = CONTENT_RULES[0]
    content = '{\n  "private_key": "-----BEGIN PRIVATE KEY-----..."\n}'
    assert list(rule.find(content)) == []


def test_high_entropy_rule_flags_a_long_random_looking_token():
    line = "token = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    findings = list(HIGH_ENTROPY_RULE.find(line, claimed_spans=[]))
    assert findings == ["wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]


def test_high_entropy_rule_ignores_low_entropy_text():
    assert list(HIGH_ENTROPY_RULE.find("this is just an ordinary sentence", claimed_spans=[])) == []


def test_high_entropy_rule_skips_a_span_already_claimed_by_a_more_specific_rule():
    # Regression test: a naive substring-based overlap check misses this case because the JWT
    # match spans the dots ('.') that the entropy candidate-token regex splits on, so the two
    # rules tokenize the line differently even though they cover the same characters.
    line = (
        "JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    jwt_rule = _RULES_BY_ID["jwt"]
    claimed_spans = [(start, end) for start, end, _ in jwt_rule.finditer(line)]
    assert claimed_spans, "the JWT rule must actually match this line for the test to be meaningful"

    assert list(HIGH_ENTROPY_RULE.find(line, claimed_spans)) == []
