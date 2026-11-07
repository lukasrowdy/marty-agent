"""Never-send screen for text leaving the Jr app for the hosted model.

ADDED 2026-09-28 (Jr overnight build, item 3 "app"). The pattern is the dashboard's
text_allowed check (a callable the send path asks at the last moment, refusing with a
fixed message; the dashboard is not imported). The term list is the owner's own JSON
file in Jr's private data root: a list of strings, each a name, number, address or
phrase that must never go out. Matching folds case and compatibility forms (NFKC) and
lets any run of punctuation or space stand between the letters and digits of a term,
so "Mary Ann" catches "Mary/Ann" and "555-123-4567" catches "(555) 123-4567". A term
never matches inside a longer word. The screen fails closed: a damaged list refuses
every text. Messages never echo a term or the text.
"""

from __future__ import annotations

import json
from pathlib import Path
import re
import unicodedata

NEVER_SEND_FILE = "never-send.json"
MAX_TERMS = 500
MAX_TERM_CHARS = 200
MAX_FILE_BYTES = 200_000
MAX_TEXT_CHARS = 200_000
REFUSED = "That text contains a never-send term. Nothing was sent."
LIST_UNAVAILABLE = "The never-send list could not be read. Nothing was sent."


class NeverSendError(Exception):
    """Fixed text only: never a term, never the checked text."""


def normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def term_pattern(term: str):
    """A compiled pattern for one term, or None when the term has no letters or digits."""
    tokens = [t for t in re.split(r"[\W_]+", normalize(term)) if t]
    if not tokens:
        return None
    body = r"[\W_]*".join(re.escape(token) for token in tokens)
    return re.compile(r"(?<![^\W_])" + body + r"(?![^\W_])")


def load_terms(path: Path) -> list[str]:
    """The owner's list, or [] when the file is absent. Raises NeverSendError when damaged."""
    path = Path(path)
    if path.is_symlink():
        raise NeverSendError(LIST_UNAVAILABLE)
    if not path.exists():
        return []
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError()
        terms = json.loads(raw)
        if (type(terms) is not list or len(terms) > MAX_TERMS or
            any(type(t) is not str or not t.strip() or len(t) > MAX_TERM_CHARS or
                any(ord(c) < 32 or ord(c) == 127 for c in t) for t in terms)):
            raise ValueError()
        return terms
    except (OSError, ValueError, TypeError, UnicodeError):
        raise NeverSendError(LIST_UNAVAILABLE) from None


class NeverSendScreen:
    """text_allowed(text) -> bool for the hosted send path; reads the list on every call."""

    def __init__(self, path):
        self.path = Path(path)

    def hit_count(self, text) -> int:
        """How many distinct terms the text contains. Raises NeverSendError when the list is damaged."""
        if type(text) is not str or len(text) > MAX_TEXT_CHARS:
            raise NeverSendError(REFUSED)
        folded = normalize(text)
        count = 0
        for term in load_terms(self.path):
            pattern = term_pattern(term)
            if pattern is not None and pattern.search(folded):
                count += 1
        return count

    def allowed(self, text) -> bool:
        """False for a hit, a damaged list, or anything that is not text. Never raises."""
        try:
            return self.hit_count(text) == 0
        except NeverSendError:
            return False

    __call__ = allowed
