"""Shannon entropy, used to flag high-entropy strings that don't match a known secret shape."""

import math
from collections import Counter

HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR = 4.5
HIGH_ENTROPY_MIN_LENGTH = 20


def shannon_entropy(text: str) -> float:
    """Average bits of information per character. Uniform random base64 lands around 6.0;
    natural-language words and hex UUIDs top out under 4.5, which is why that's the threshold."""
    if not text:
        return 0.0

    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def is_high_entropy_secret(candidate: str) -> bool:
    """True when `candidate` is long enough and random-looking enough to be treated as a secret
    on its own, independent of any specific token shape or surrounding assignment context."""
    return (
        len(candidate) >= HIGH_ENTROPY_MIN_LENGTH
        and shannon_entropy(candidate) >= HIGH_ENTROPY_THRESHOLD_BITS_PER_CHAR
    )
