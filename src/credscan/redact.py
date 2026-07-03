"""Never print a raw secret to stdout/CI logs — only a short, non-reversible preview."""

_VISIBLE_PREFIX = 4
_VISIBLE_SUFFIX = 2
_MIN_LENGTH_TO_SHOW_SUFFIX = 8


def redact(value: str) -> str:
    if len(value) <= _VISIBLE_PREFIX:
        return "*" * len(value)
    if len(value) < _MIN_LENGTH_TO_SHOW_SUFFIX:
        return value[:_VISIBLE_PREFIX] + "*" * (len(value) - _VISIBLE_PREFIX)
    masked_length = len(value) - _VISIBLE_PREFIX - _VISIBLE_SUFFIX
    return value[:_VISIBLE_PREFIX] + "*" * masked_length + value[-_VISIBLE_SUFFIX:]
