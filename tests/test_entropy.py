from credscan.entropy import shannon_entropy


def test_empty_string_has_zero_entropy():
    assert shannon_entropy("") == 0.0


def test_single_repeated_character_has_zero_entropy():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_hex_uuid_like_string_is_below_the_high_entropy_threshold():
    # 16-symbol alphabet caps entropy at exactly 4.0 bits/char for a perfectly uniform sample.
    assert shannon_entropy("0123456789abcdef") <= 4.0


def test_random_looking_base64_string_exceeds_the_high_entropy_threshold():
    assert shannon_entropy("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") > 4.5


def test_english_word_has_low_entropy():
    assert shannon_entropy("password") < 3.5
