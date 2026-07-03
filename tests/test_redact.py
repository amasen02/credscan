from credscan.redact import redact


def test_short_value_is_fully_masked():
    assert redact("ab") == "**"


def test_medium_value_shows_only_the_prefix():
    assert redact("abcdef") == "abcd**"


def test_long_value_shows_prefix_and_suffix_with_masked_middle():
    result = redact("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AKIA")
    assert result.endswith("LE")
    assert "*" in result
    assert len(result) == len("AKIAIOSFODNN7EXAMPLE")


def test_redaction_never_reveals_more_than_prefix_and_suffix():
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    result = redact(secret)
    middle = secret[4:-2]
    assert middle not in result
