"""
Marty Jr.'s encrypted history, its lock, and the never-send list
(MJ Dashboard Phase 2: W3's storage and lock, W4's never-send list and check; 2026-09-25).

EncryptedJrStore replaces jr_lane.MemoryJrStore behind the same four-method JrStore seam
(create_thread / list_threads / get_thread / append_turn), and adds the lock and the
never-send list. The lane never touches storage any other way.

ON DISK, in my-agent/jr/history (jr_tools.HISTORY_DIR, a deny_dir of Jr's own fence, so his
tools can never read it):
    keyinfo.json      the salt, the Argon2id settings and a key-check value. Nothing secret:
                      the check is an AES-GCM encryption of a fixed string, so a wrong
                      passphrase is caught without opening any thread.
    index.bin         encrypted: each thread's id, owner handle, title, times and turn count
    <thread id>.bin   encrypted: one whole thread, rewritten on every append
    never-send.bin    encrypted: Lukas's never-send terms
  Every .bin file is  b"JRS" + format byte | 12-byte random nonce | AES-256-GCM ciphertext
  and tag. Each write draws a fresh nonce, and the AAD binds the format, the kind of blob and
  its id, so a blob cannot be moved to another thread or role, and a single flipped byte is
  refused (StoreCorrupt). Writes are atomic: a uniquely named temp file in the same folder,
  fsync, then os.replace, retried briefly while another process (a backup tool, an antivirus
  scan) has the target open, because on Windows os.replace fails with PermissionError then.

THE KEY. Argon2id (cryptography's KDF: 256 MiB, 3 passes, 4 lanes, about 0.2 s here) from
the passphrase Lukas types, NFC-normalised so a phone and a PC give the same bytes, with a
random 16-byte salt. The key exists only in this object's memory while unlocked. The key and
the passphrase are never written, logged, returned or put in an exception. Locking zeroes
the key buffer and drops the cipher (best effort: Python cannot promise every copy is gone).

THE LOCK. Locked at start (so a restart locks), lock() on demand (logout, the page going to
the background), and after IDLE_SECONDS without use, by a timer, so the key is dropped even
if no request ever comes. unlock() allows UNLOCK_TRIES wrong passphrases per UNLOCK_WINDOW,
counted in memory and checked BEFORE the KDF runs, so a refused try costs nothing and tells
nothing. The first unlock with no keyinfo.json is the setup: the passphrase must have at
least PASSPHRASE_MIN characters (the page asks for it twice). Setup refuses to start a new
key over existing encrypted history.

NEVER-SEND. Terms Lukas types (names, school, address), kept only inside the encrypted
store. handoff_check(text) finds them ignoring case and accents. Text and terms are folded the
same way, one character at a time so every hit maps back to the original text: invisible
format and joiner characters and lone surrogates are stripped; apostrophes and dashes are
straightened; blank letters (Hangul fillers, the blank braille cell) are stripped too;
compatibility forms are mapped the way NFKC maps them (full-width, circled, parenthesized and
math letters, ligatures; done as NFKD with the accents then dropped, which is NFKC's mapping
plus accent folding); look-alike letters become the Latin letter they imitate (a TR39-style
subset, _CONFUSABLE and _TRANSLIT: Cyrillic А В Е К М Н О Р С Т Х У І Ј Ѕ and more, with the
small forms, including the small-capital-looking в к м н т; Greek Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ
and α γ η ι κ ν ο ρ τ υ χ μ; 19 Cherokee capitals; the Latin small capitals ᴀ to ᴢ, ɑ, ɡ, ı,
ȷ, and any Latin letter with a stroke, hook or bar, read from its Unicode name), capitals
before casefolding; then everything is casefolded. So "Tаmsin" with a Cyrillic a, "Tɑmsin"
with a Latin alpha, "Tᴀmsin", an all-Cyrillic "ТОМ", an all-Greek "ΕΜΜΑ" and a full-width
"Ｔａｍｓｉｎ" all hit their term. The palochka (ӏ, Ӏ) passes for both a capital I and a small
l, so it matches either.
Separately, while the list holds any term, a word that mixes letters of two or more alphabets
is a hit too (reason "mixed-script word"), whatever it spells: Latin with Cyrillic, Cyrillic
with Greek and no Latin at all, Latin with Armenian. It fails closed on mixed look-alikes
outside the subset above. Japanese and Korean kana, hangul and ideographs count as one
alphabet. Modifier letters, and the math and unit letters μ Ω π Δ Σ θ λ (the micro and ohm
signs map to μ and Ω), count as none, so "2πr", "Δx", "5 µs" and "3 kΩ" pass; the trade-off is
that one of those letters inside a Latin word is not flagged either (μ, which does pass for a
u, is folded to u, so it cannot hide a term). A word is a run of letters; marks and invisible
characters inside it do not split it, and anything else does.
A term that starts or ends with a letter is not matched inside a longer word ("Ann" is not
in "annual"), but a digit, an underscore or punctuation next to it does not hide it
("tamsin_report", "tamsin2024@"), and a term that ends in a digit is not matched inside a
longer number. It also catches possessives and plurals ('s, s', es, s), curly apostrophes,
odd dashes, invisible format and joiner characters, lone surrogates, and letters like
l-stroke, o-slash and sharp s. Hits are offsets into the text, each with a fixed reason
("never-send term" or "mixed-script word"); no error message ever quotes a term.

Known limits: file sizes and times show roughly how long and how recent a thread is; an
older copy of a thread file restored whole is accepted (no rollback check); a turn that
finishes while the store is locked is held in memory (the lane already holds it there) and
written at the next unlock, or lost if the server stops first; the wrong-passphrase count
is in memory, so a restart resets it, and anyone with a device login can keep it tripped; a
word written ENTIRELY in one alphabet's look-alikes that are outside the subset above (all
Armenian, say, or Cherokee letters left out of the table) is neither folded nor mixed-script,
so it is not matched; regional-indicator letters (the ones flags are made of) are not read
as letters, because folding them would glue a flag to the next word and hide it.
A damaged index is set aside and rebuilt from the thread files (which carry the same facts
and are authenticated); status()["notices"] says so. A thread file that disappears (deleted
or moved outside the dashboard) is never dropped silently: its index entry moves to a
"missing" record, missing_threads(handle) counts those for the thread list, and
take_missing_found() reports the ones found at the last unlock once, for the server's log
(counts only). A file that comes back is listed again. When the deletion was deliberate,
dismiss_missing(handle) forgets that handle's records (the Jr view's Dismiss).

This module never prints and never logs.

    py test_jr_store.py -v
"""

from __future__ import annotations

import base64
import copy
import json
import os
import pathlib
import re
import secrets
import threading
import time
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

import jr_lane
import jr_tools

# One definition, shared with Jr's fence. MARTY_JR_HISTORY points a TEST server at a temp
# folder, so a test passphrase can never set up the real history before Lukas does.
HISTORY_DIR = pathlib.Path(os.environ.get("MARTY_JR_HISTORY") or jr_tools.HISTORY_DIR)

FORMAT = 1
MAGIC = b"JRS" + bytes([FORMAT])
NONCE_BYTES = 12
TAG_BYTES = 16
KEY_BYTES = 32
SALT_BYTES = 16
KDF_DEFAULT = {"iterations": 3, "lanes": 4, "memory_kib": 256 * 1024}
KDF_FLOOR = {"iterations": 1, "lanes": 1, "memory_kib": 64 * 1024}       # refuse a weakened keyinfo
KDF_CEILING = {"iterations": 16, "lanes": 16, "memory_kib": 1024 * 1024}  # refuse a keyinfo built to stall us
PASSPHRASE_MIN = 12
PASSPHRASE_MAX = 1024
IDLE_SECONDS = 15 * 60
UNLOCK_TRIES = 5
UNLOCK_WINDOW = 10 * 60
MAX_PENDING = 32
NEVER_SEND_MAX_TERMS = 500
TERM_MIN = 2                  # letters or digits in a term
TERM_MAX = 200
HANDOFF_MAX = 200_000
REPLACE_TRIES = 60
REPLACE_WAIT = 0.025

KEYINFO = "keyinfo.json"
INDEX = "index.bin"
NEVER_SEND = "never-send.bin"
CHECK_TEXT = b"marty-jr history key check"
THREAD_FILE = re.compile(r"^([0-9a-f]{16})\.bin\Z")
TEMP_FILE = re.compile(r"^\..+\.[0-9a-f]{12}\.tmp\Z")
ID_RE = jr_lane.ID_RE


class StoreError(Exception):
    """Base class. Messages are fixed text: never a passphrase, a key, a term or Jr's text."""


class Locked(StoreError):
    pass


class RateLimited(StoreError):
    def __init__(self, retry_after: int):
        super().__init__(f"too many wrong passphrases; try again in {retry_after} s")
        self.retry_after = retry_after


class WeakPassphrase(StoreError, ValueError):
    pass


class StoreCorrupt(StoreError):
    pass


class StoreBusy(StoreError):
    pass


# ---------------------------------------------------------------------------- file helpers

def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _unb64(text) -> bytes:
    if not isinstance(text, str):
        raise ValueError("not base64 text")
    return base64.b64decode(text.encode("ascii"), validate=True)


def _aad(kind: str, ident: str) -> bytes:
    return MAGIC + b"|" + kind.encode("ascii") + b"|" + ident.encode("utf-8")


def _read_bytes(path: pathlib.Path) -> bytes:
    """Read a whole file, retrying briefly if another process is renaming over it."""
    for attempt in range(REPLACE_TRIES):
        try:
            with open(path, "rb") as f:
                return f.read()
        except PermissionError:
            if attempt == REPLACE_TRIES - 1:
                raise StoreBusy("a history file stayed locked by another program") from None
            time.sleep(REPLACE_WAIT)
    raise StoreBusy("a history file stayed locked by another program")


# ---------------------------------------------------------------------------- never-send matching

_ZERO_WIDTH = frozenset("\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e")
_APOSTROPHES = frozenset("\u2019\u2018\u02bc\u2032\u00b4\uff07")
_DASHES = frozenset("\u2010\u2011\u2012\u2013\u2014\u2015\u2212\ufe63\uff0d")
_TRANSLIT = {"\u0142": "l", "\u0141": "L", "\u00f8": "o", "\u00d8": "O", "\u00e6": "ae", "\u00c6": "AE",
             "\u0153": "oe", "\u0152": "OE", "\u00df": "ss", "\u1e9e": "SS", "\u0111": "d", "\u0110": "D",
             "\u00f0": "d", "\u00d0": "D", "\u00fe": "th", "\u00de": "TH", "\u0131": "i", "\u0127": "h",
             "\u0126": "H", "ŀ": "l", "Ŀ": "L",   # letters NFKD leaves alone
             # Latin-script look-alikes (skeptic, 2026-09-25). They ARE Latin, so the mixed-script
             # rule cannot see them: Latin alpha, script g, iota, dotless j, the dental click (a
             # bar like l), and the small capitals A to Z. _latin_base() covers the rest of the
             # Latin letters NFKD leaves alone (hooks, strokes, bars) by their Unicode names.
             # (the dental click folds to the palochka, so like it it passes for an I or an l)
             "\u0251": "a", "\u0261": "g", "\u0269": "i", "\u0237": "j", "\u01c0": "\u04cf",
             "\u1d00": "a", "\u0299": "b", "\u1d04": "c", "\u1d05": "d", "\u1d07": "e", "\ua730": "f",
             "\u0262": "g", "\u029c": "h", "\u026a": "i", "\u1d0a": "j", "\u1d0b": "k", "\u029f": "l",
             "\u1d0d": "m", "\u0274": "n", "\u1d0f": "o", "\u1d18": "p", "\ua7af": "q", "\u0280": "r",
             "\ua731": "s", "\u1d1b": "t", "\u1d1c": "u", "\u1d20": "v", "\u1d21": "w", "\u028f": "y",
             "\u1d22": "z"}
_MARKS = ("Mn", "Me")          # combining accents, joiners (U+034F), variation selectors
# Characters that draw nothing but are not format characters: the Hangul fillers and the blank
# braille cell. Stripped like the zero-width ones, so "Tam" + filler + "sin" is "Tamsin".
_BLANKS = frozenset("\u115f\u1160\u3164\uffa0\u2800")
# Math and unit letters that are NOT Latin look-alikes: neutral for the mixed-script rule, so
# "2πr", "Δx", "5 µs" and "3 kΩ" pass (the micro and ohm signs map to μ and Ω first). Trade-off:
# one of them inside a Latin word is not flagged either. None of them joins a term's letters
# except μ, which does pass for a u and so is also folded to u (_CONFUSABLE).
_MATH_NEUTRAL = frozenset("\u03bc\u03a9\u03c0\u0394\u03a3\u03c3\u03b8\u03bb")
# Japanese and Korean words mix these legitimately; for the mixed-script rule they are one
# family (as in TR39's Highly Restrictive profile). Latin with any of them is still mixed.
_SCRIPT_GROUPS = {"CJK": "HAN", "HIRAGANA": "HAN", "KATAKANA": "HAN", "KATAKANA-HIRAGANA": "HAN",
                  "HANGUL": "HAN", "BOPOMOFO": "HAN", "IDEOGRAPHIC": "HAN"}
_LATIN_NAME = re.compile(r"^LATIN (?:(SMALL|CAPITAL) LETTER (?:DOTLESS |SCRIPT )?|LETTER SMALL CAPITAL "
                         r"|SMALL CAPITAL LETTER )([A-Z])(?: WITH .+)?\Z")
_PARENTHESIZED = re.compile(r"^\(([^\W_]+)\)\Z")    # NFKD of a parenthesized letter: "(t)"
_SEP = r"[\W_]*"               # between a term's words: any run of non-letters, or none
_fold_cache: dict = {}

# Look-alike letters from other alphabets, folded to the Latin letter they imitate before any
# matching: a TR39-style subset, the Cyrillic, Greek and Cherokee letters that pass for Latin in
# most fonts. Capitals fold to capitals BEFORE casefolding, because a capital can imitate a
# different letter than its own small form (Greek capital nu looks like N, small nu like v;
# Cyrillic capital Н is H, small н is a small-capital h). A capital with no entry of its own
# takes its small form's (and a Cherokee small letter its capital's, since Cherokee casefolds
# upward); an entry that maps a letter to itself stops that (Greek capital gamma is no Y).
_CONFUSABLE = {
    # Cyrillic capital: А В Е К М Н О Р С Т Х У І Ј Ѕ Ԁ Ԛ Ԝ Ү Һ Ѵ
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H",
    "\u041e": "O", "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0423": "Y",
    "\u0406": "I", "\u0408": "J", "\u0405": "S", "\u0500": "D", "\u051a": "Q", "\u051c": "W",
    "\u04ae": "Y", "\u04ba": "H", "\u0474": "V",
    # Cyrillic small: а в е к м н о р с т х у і ј ѕ ԁ ԛ ԝ ү һ ѵ (в к м н т are small capitals)
    "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u043a": "k", "\u043c": "m", "\u043d": "h",
    "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0445": "x", "\u0443": "y",
    "\u0456": "i", "\u0458": "j", "\u0455": "s", "\u0501": "d", "\u051b": "q", "\u051d": "w",
    "\u04af": "y", "\u04bb": "h", "\u0475": "v",
    # The palochka (ӏ, capital Ӏ) passes for both a capital I and a small l, so it is not
    # turned into either: both forms fold to the small one, and every i or l in a term also
    # accepts it (_PAL_CLASS).
    "\u04c0": "\u04cf",
    # Greek capital: Α Β Ε Ζ Η Ι Κ Μ Ν Ο Ρ Τ Υ Χ Ϲ Ϳ Ϝ, and Γ kept as itself (its small form γ is y)
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I",
    "\u039a": "K", "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X", "\u03f9": "C", "\u037f": "J", "\u03dc": "F", "\u0393": "\u0393",
    # Greek small: α γ η ι κ ν ο ρ τ υ χ ϲ ϳ, and μ (a u with a tail; also neutral as a unit)
    "\u03b1": "a", "\u03b3": "y", "\u03b7": "n", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v",
    "\u03bf": "o", "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03f2": "c",
    "\u03f3": "j", "\u03bc": "u",
    # Cherokee capital, each checked by eye in the Gadugi font: Ꭺ Ᏼ Ꮯ Ꭰ Ꭼ Ꮐ Ꮋ Ꭵ Ꭻ Ꮶ Ꮮ Ꮇ Ꮲ Ꭱ Ꮪ Ꭲ Ꮩ Ꮃ Ꮓ
    # (Ꮎ reads as a theta, not an O, so it is left out)
    "\u13aa": "A", "\u13f4": "B", "\u13df": "C", "\u13a0": "D", "\u13ac": "E", "\u13c0": "G",
    "\u13bb": "H", "\u13a5": "i", "\u13ab": "J", "\u13e6": "K", "\u13de": "L", "\u13b7": "M",
    "\u13e2": "P", "\u13a1": "R", "\u13da": "S", "\u13a2": "T", "\u13d9": "V", "\u13b3": "W",
    "\u13c3": "Z",
}
_PAL = "\u04cf"
_PAL_CLASS = {"i": "[i\u04cf]", "l": "[l\u04cf]", _PAL: "[il\u04cf]"}

REASON_TERM = "never-send term"
REASON_MIXED = "mixed-script word"
_NEUTRAL_SCRIPTS = frozenset({"MODIFIER"})   # modifier letters (IPA length marks) belong to no alphabet
_script_cache: dict = {}


def _strip_marks(text: str) -> str:
    return "".join(c for c in text if unicodedata.category(c) not in _MARKS)


def _latin_base(c: str):
    """The plain letter of a Latin letter NFKD leaves alone, from its Unicode name: "LATIN SMALL
    LETTER T WITH STROKE", "... D WITH HOOK", "... DOTLESS J", "LATIN LETTER SMALL CAPITAL R".
    None for anything else (turned, reversed or open letters look like something else)."""
    m = _LATIN_NAME.match(unicodedata.name(c, ""))
    if not m:
        return None
    return m.group(2) if m.group(1) == "CAPITAL" else m.group(2).lower()


def _look(c: str):
    """The Latin letters one code point passes for, or None."""
    return _CONFUSABLE.get(c) or _TRANSLIT.get(c) or _latin_base(c)


def _fold_char(ch: str) -> str:
    """One character, folded for matching. Invisible format and joiner characters, blank
    letters and lone surrogates vanish; apostrophes and dashes are straightened. Anything else:
    compatibility forms are mapped (NFKD, so full-width, circled, parenthesized and math letters
    and ligatures become plain ones, as NFKC would map them) and accents dropped, look-alike
    letters become the Latin letter they imitate (capitals before casefolding), and the result is
    casefolded."""
    out = _fold_cache.get(ch)
    if out is None:
        if ch in _ZERO_WIDTH or ch in _BLANKS or unicodedata.category(ch) in ("Cf", "Cs"):
            out = ""                            # invisible format marks, blanks, lone surrogates
        elif ch in _APOSTROPHES:
            out = "'"
        elif ch in _DASHES:
            out = "-"
        else:
            base = _TRANSLIT.get(ch)
            if base is None:
                base = _strip_marks(unicodedata.normalize("NFKD", ch))
                paren = _PARENTHESIZED.match(base)
                if paren:
                    base = paren.group(1)
            parts = []
            for c in base:
                piece = c if c.isascii() else _look(c)
                if piece is None:
                    # No entry of its own: a capital takes its small form's (Latin capital alpha
                    # is a), a Cherokee small letter its capital's (Cherokee casefolds upward).
                    low = c.casefold()
                    piece = "".join(_look(x) or x for x in low) if low != c else c
                parts.append(piece)
            out = _strip_marks(unicodedata.normalize("NFKD", "".join(parts).casefold()))
        if len(_fold_cache) < 8192:
            _fold_cache[ch] = out
    return out


def _char_script(ch: str):
    """The alphabet a character's letters belong to ("LATIN", "CYRILLIC", "GREEK", "HAN", ...),
    "NEUTRAL" for letters of no alphabet in particular (modifier letters, the math and unit
    letters in _MATH_NEUTRAL), "" for an invisible character that sits inside a word (a mark, a
    joiner, a format character, a blank letter), or None for anything that ends a word.
    Compatibility forms count as what they map to (a full-width A is Latin, the micro sign μ)."""
    if ch.isascii():
        return "LATIN" if ch.isalpha() else None
    out = _script_cache.get(ch, False)
    if out is False:
        cat = unicodedata.category(ch)
        if ch in _ZERO_WIDTH or ch in _BLANKS or cat in ("Cf", "Cs") or cat[0] == "M":
            out = ""
        elif ch in _APOSTROPHES or ch in _DASHES:
            out = None
        else:
            letters = [c for c in unicodedata.normalize("NFKD", _TRANSLIT.get(ch, ch)) if c.isalpha()]
            if not letters:
                out = None
            elif letters[0] in _MATH_NEUTRAL:
                out = "NEUTRAL"
            else:
                word = (unicodedata.name(letters[0], "") or "UNKNOWN").split(" ", 1)[0]
                out = "NEUTRAL" if word in _NEUTRAL_SCRIPTS else _SCRIPT_GROUPS.get(word, word)
        if len(_script_cache) < 8192:
            _script_cache[ch] = out
    return out


def _mixed_script_words(text: str) -> list:
    """(start, end) code-point spans of the words that mix letters of two or more alphabets,
    e.g. "Tаmsin" with a Cyrillic a, or Cyrillic and Greek with no Latin at all. A word is a run
    of letters; marks, joiners and format characters inside it do not split it; digits, spaces
    and punctuation do. Neutral letters (modifier letters, math and unit letters) count for none."""
    if text.isascii():
        return []
    spans, start, end, scripts = [], None, None, set()

    def close():
        if start is not None and len(scripts - {"NEUTRAL"}) > 1:
            spans.append((start, end))
    for i, ch in enumerate(text):
        kind = _char_script(ch)
        if kind is None:
            close()
            start, scripts = None, set()
        elif kind == "":
            if start is not None:
                end = i + 1
        else:
            if start is None:
                start, scripts = i, set()
            scripts.add(kind)
            end = i + 1
    close()
    return spans


def _fold(text: str):
    """(folded text, index map). Folding drops accents and zero-width characters and
    straightens apostrophes and dashes; the map gives, for each folded character, the index
    of the character it came from (None when the text is ASCII and nothing moves)."""
    if text.isascii():
        return text, None
    out, idx = [], []
    for i, ch in enumerate(text):
        if ch.isascii():
            out.append(ch)
            idx.append(i)
            continue
        for c in _fold_char(ch):
            out.append(c)
            idx.append(i)
    return "".join(out), idx


def _edge_kind(ch: str):
    """What a neighbour must not be for a match to count as a whole word: a letter next to a
    letter, a digit next to a digit. Underscores, other digits and punctuation never hide a
    term, so "tamsin_report" and "tamsin2024@" still hit "Tamsin"."""
    if ch.isalpha():
        return "alpha"
    if ch.isdigit():
        return "digit"
    return None


def _joins(kind, ch: str) -> bool:
    return (kind == "alpha" and ch.isalpha()) or (kind == "digit" and ch.isdigit())


def _token_rx(token: str, palochka: bool) -> str:
    if not palochka:
        return re.escape(token)
    return "".join(_PAL_CLASS.get(c.lower(), re.escape(c)) for c in token)


def _term_matcher(term: str):
    """(pattern, pattern for text that holds a palochka, what may not sit on its left) for one
    term, or None. The second pattern lets a palochka stand for any i or l in the term; it is
    used only for text that holds one, so ordinary text keeps the literal-first fast path."""
    folded, _ = _fold(term)
    folded = re.sub(r"'s?\Z", "", folded.strip(), flags=re.IGNORECASE) or folded
    # Letters and digits only; any run of anything else between them may be anything else
    # (or nothing): "555-123-4567" catches "(555) 123-4567", "Mary Ann" catches "Mary/Ann",
    # "O'Brien" catches "OBrien".
    tokens = [t for t in re.split(r"[\W_]+", folded) if t]
    if not tokens:
        return None
    right = _edge_kind(tokens[-1][-1])
    if right == "alpha":
        tail = r"(?:'s|es'|s'|es|'|s)?(?![^\W\d_])"   # possessive/plural, then no further letter
    elif right == "digit":
        tail = r"(?!\d)"
    else:
        tail = ""
    # The left boundary is checked in code, not with a lookbehind: a pattern that starts
    # with a literal lets the regex engine skip ahead, about 2.7x faster over 500 terms.
    plain = re.compile(_SEP.join(_token_rx(t, False) for t in tokens) + tail, re.IGNORECASE)
    if any(c in "iIlL" + _PAL for c in folded):
        pal = re.compile(_SEP.join(_token_rx(t, True) for t in tokens) + tail, re.IGNORECASE)
    else:
        pal = plain
    return plain, pal, _edge_kind(tokens[0][0])


def _clean_terms(terms) -> list:
    """Validate and normalise a never-send list. Errors name a term by its position only."""
    if not isinstance(terms, (list, tuple)):
        raise ValueError("the never-send list must be a list of strings")
    if len(terms) > NEVER_SEND_MAX_TERMS:
        raise ValueError(f"the never-send list holds at most {NEVER_SEND_MAX_TERMS} terms")
    out, seen = [], set()
    for i, term in enumerate(terms, 1):
        if not isinstance(term, str):
            raise ValueError(f"term {i} is not text")
        term = " ".join(unicodedata.normalize("NFC", term).split())
        if not term:
            continue
        if len(term) > TERM_MAX:
            raise ValueError(f"term {i} is longer than {TERM_MAX} characters")
        if any(unicodedata.category(c) in ("Cc", "Cs") for c in term):
            raise ValueError(f"term {i} contains control characters")
        folded, _ = _fold(term)
        if sum(1 for c in folded if c.isalnum()) < TERM_MIN:
            raise ValueError(f"term {i} needs at least {TERM_MIN} letters or digits")
        key = " ".join(t for t in re.split(r"[\W_]+", folded.casefold()) if t)
        if key in seen:
            continue
        seen.add(key)
        out.append(term)
    return out


def find_hits(text: str, matchers) -> list:
    """Merged, non-overlapping hits as [{"start", "end", "term", "reason"}], code-point
    offsets. reason is REASON_TERM for a never-send term (term names it) or REASON_MIXED for a
    word that mixes Latin letters with another alphabet (term is None). Mixed-script words
    count only while there is a list to protect; a hit that is both says REASON_TERM."""
    folded, idx = _fold(text)
    palochka = idx is not None and _PAL in folded
    found = []
    for (plain, pal, left), term in matchers:
        rx = pal if palochka else plain
        pos = 0
        while pos <= len(folded):
            m = rx.search(folded, pos)
            if not m:
                break
            s, e = m.span()
            if e <= s:
                pos = s + 1
                continue
            if left and s > 0 and _joins(left, folded[s - 1]):
                pos = s + 1                     # inside a longer word: look again one further on
                continue
            if idx is None:
                start, end = s, e
            else:
                start, end = idx[s], idx[e - 1] + 1
                while end < len(text) and unicodedata.category(text[end]) in _MARKS:
                    end += 1                    # keep an accent that follows the last letter
            found.append((start, end, term))
            pos = e
    if matchers:
        found.extend((start, end, None) for start, end in _mixed_script_words(text))
    found.sort(key=lambda h: (h[0], -h[1]))
    merged = []
    for start, end, term in found:
        if merged and start < merged[-1]["end"]:
            last = merged[-1]
            last["end"] = max(last["end"], end)
            if last["term"] is None and term is not None:
                last["term"], last["reason"] = term, REASON_TERM
        else:
            merged.append({"start": start, "end": end, "term": term,
                           "reason": REASON_TERM if term is not None else REASON_MIXED})
    return merged


def utf16_offsets(text: str, hits: list) -> list:
    """The same hits with offsets in UTF-16 code units, which is what a browser's strings use
    (an emoji is one code point in Python and two units in JavaScript)."""
    if all(ord(c) <= 0xFFFF for c in text):
        return [dict(h) for h in hits]
    pre = [0]
    for c in text:
        pre.append(pre[-1] + (2 if ord(c) > 0xFFFF else 1))
    return [dict(h, start=pre[h["start"]], end=pre[h["end"]]) for h in hits]


def _check_turn(turn) -> None:
    """A turn must be storable before it is accepted, so a bad one fails at once for its
    caller, never later inside an unlock. Messages never quote the turn."""
    if not isinstance(turn, dict):
        raise ValueError("a turn must be an object")
    for field in ("id", "user", "reply"):
        if turn.get(field) is not None and not isinstance(turn.get(field), str):
            raise ValueError("a turn's id, user and reply must be text")
    try:
        json.dumps(turn)
    except (TypeError, ValueError, RecursionError):
        raise ValueError("a turn holds something that cannot be stored") from None


# ---------------------------------------------------------------------------- the store

class EncryptedJrStore(jr_lane.JrStore):
    def __init__(self, root=None, idle_seconds: float = IDLE_SECONDS, clock=time.monotonic,
                 kdf: dict | None = None, unlock_tries: int = UNLOCK_TRIES,
                 unlock_window: float = UNLOCK_WINDOW):
        self.root = pathlib.Path(root) if root is not None else pathlib.Path(HISTORY_DIR)
        self.idle_seconds = float(idle_seconds)
        self.unlock_tries = int(unlock_tries)
        self.unlock_window = float(unlock_window)
        self._clock = clock
        self._kdf_setup = self._check_params(dict(kdf or KDF_DEFAULT))    # used only by setup
        self._lock = threading.RLock()          # key, index and every write
        self._gate = threading.Lock()           # one unlock (one 256 MiB KDF) at a time
        self._key = None                        # bytearray while unlocked
        self._aead = None
        self._index = None
        self._never = None
        self._matchers = None
        self._last_used = 0.0
        self._failures = []
        self._pending = []
        self._notices = set()                   # codes only, e.g. "index_rebuilt"; never content
        self._missing_found = 0                 # thread files found gone at the last unlock (a count)
        self._timer = None
        self.epoch = None                       # a fresh random id at every unlock: lets the server bind each open
                                                # to the device sessions that typed the passphrase
        # Called (on a thread of their own, so no lock order can deadlock) every time the key is
        # dropped: by lock(), by the idle timer, or by use after the idle time. The server
        # registers the lane's purge here, so Jr's finished replies leave memory with the key.
        self.on_lock = []
        self.kdf_runs = 0                       # counters for the tests; no secrets in them
        self.write_retries = 0

    def __repr__(self):
        return f"<EncryptedJrStore {'unlocked' if self._aead is not None else 'locked'}>"

    # -------------------------------------------------------------- lock state

    def needs_setup(self) -> bool:
        return not (self.root / KEYINFO).exists()

    def is_unlocked(self) -> bool:
        with self._lock:
            self._expire_if_idle()
            return self._aead is not None

    def seconds_until_lock(self):
        with self._lock:
            self._expire_if_idle()
            if self._aead is None:
                return None
            return max(0.0, self.idle_seconds - (self._clock() - self._last_used))

    def status(self) -> dict:
        """What the page may know: locked or not, first-time setup or not, and when it locks."""
        left = self.seconds_until_lock()
        return {"unlocked": left is not None, "needs_setup": self.needs_setup(),
                "locks_in": None if left is None else int(left),
                "notices": sorted(self._notices) if left is not None else []}

    def touch(self) -> bool:
        """Count a request as use (resets the idle clock). False when locked."""
        with self._lock:
            self._expire_if_idle()
            if self._aead is None:
                return False
            self._last_used = self._clock()
            return True

    def lock(self) -> None:
        with self._lock:
            self._drop_key()

    def unlock(self, passphrase) -> bool:
        """True when unlocked (or set up, the first time). False for a wrong passphrase.
        Raises RateLimited after too many wrong ones, WeakPassphrase for a too-short first
        passphrase, StoreCorrupt when the history on disk fails its integrity check."""
        if not isinstance(passphrase, str) or not passphrase:
            return False
        with self._gate:
            now = self._clock()
            with self._lock:
                self._failures = [t for t in self._failures if now - t < self.unlock_window]
                if len(self._failures) >= self.unlock_tries:
                    retry = int(self.unlock_window - (now - self._failures[0])) + 1
                    raise RateLimited(max(1, retry))
            text = unicodedata.normalize("NFC", passphrase)
            if any("\ud800" <= c <= "\udfff" for c in text):
                # A lone surrogate cannot be encoded; the encoder's error would quote the whole
                # passphrase, so refuse here, before anything tries.
                if self.needs_setup():
                    raise WeakPassphrase("the passphrase contains characters that cannot be stored")
                self._fail()
                return False
            if self.needs_setup():
                return self._setup(text)
            if len(text) > PASSPHRASE_MAX:
                self._fail()
                return False
            info = self._load_keyinfo()
            pw = bytearray(text.encode("utf-8"))
            try:
                key = self._derive(pw, info["salt"], info["params"])
            finally:
                pw[:] = bytes(len(pw))
            aead = AESGCM(key)
            try:
                check = info["check"]
                if aead.decrypt(check[:NONCE_BYTES], check[NONCE_BYTES:], info["check_aad"]) != CHECK_TEXT:
                    raise InvalidTag()
            except InvalidTag:
                key[:] = bytes(len(key))
                self._fail()
                return False
            with self._lock:
                self._failures.clear()
                if self._aead is not None:
                    key[:] = bytes(len(key))    # already open with this same key; a right answer is use
                    self._last_used = self._clock()
                    return True
                self._install(key, aead)
            return True

    # -------------------------------------------------------------- the seam (JrStore)

    def create_thread(self, handle):
        with self._lock:
            self._require()
            threads, gone = self._index["threads"], self._index.get("missing") or {}
            tid = secrets.token_hex(8)
            while tid in threads or tid in gone or (self.root / f"{tid}.bin").exists():
                tid = secrets.token_hex(8)
            now = jr_lane._now()
            thread = {"id": tid, "handle": handle, "title": "", "created": now, "updated": now, "turns": []}
            size = self._write_thread(thread)
            threads[tid] = {"handle": handle, "title": "", "created": now, "updated": now, "turns": 0,
                            "size": size}
            try:
                self._write_index()
            except Exception:
                threads.pop(tid, None)          # the orphan file is picked up at the next unlock
                raise
            return self._view(thread)

    def list_threads(self, handle):
        with self._lock:
            self._require()
            rows = [{"id": tid, "title": e["title"], "created": e["created"], "updated": e["updated"],
                     "turns": e["turns"]} for tid, e in self._index["threads"].items() if e["handle"] == handle]
        return sorted(rows, key=lambda r: (r["updated"], r["created"]), reverse=True)

    def missing_threads(self, handle) -> int:
        """How many of this handle's threads are gone from disk (their file was deleted or
        moved outside the dashboard). Kept in the encrypted index until the file comes back."""
        with self._lock:
            self._require()
            return sum(1 for e in (self._index.get("missing") or {}).values() if e.get("handle") == handle)

    def dismiss_missing(self, handle) -> int:
        """Forget this handle's missing-thread records: Lukas dismissed the notice because the
        deletion was deliberate. Written to the encrypted index at once; a file that comes back
        later is still listed again. Returns how many are left for the handle (0)."""
        with self._lock:
            self._require()
            gone = self._index.get("missing") or {}
            mine = [tid for tid, e in gone.items() if e.get("handle") == handle]
            if mine:
                before = copy.deepcopy(gone)
                for tid in mine:
                    del gone[tid]
                try:
                    self._write_index()
                except Exception:
                    self._index["missing"] = before     # nothing changed on disk: keep the count
                    raise
            return sum(1 for e in gone.values() if e.get("handle") == handle)

    def take_missing_found(self) -> int:
        """The number of thread files found missing at the last unlock, once: the server logs it.
        A count only, never an id or a title."""
        with self._lock:
            n, self._missing_found = self._missing_found, 0
            return n

    def get_thread(self, handle, thread_id):
        if not isinstance(thread_id, str) or not ID_RE.match(thread_id):
            return None
        with self._lock:
            self._require()
            entry = self._index["threads"].get(thread_id)
            if entry is None or entry["handle"] != handle:
                return None
            return self._view(self._read_thread(thread_id, handle))

    def append_turn(self, handle, thread_id, turn):
        _check_turn(turn)
        with self._lock:
            self._expire_if_idle()
            if self._aead is None:
                # A turn that finishes after the page locked Jr: keep it until the next unlock
                # (the lane holds the same text in memory anyway), rather than lose the reply.
                if len(self._pending) >= MAX_PENDING:
                    raise Locked("Marty Jr.'s history is locked")
                self._pending.append((handle, thread_id, copy.deepcopy(turn)))
                return
            self._require()
            self._append(handle, thread_id, turn)

    # -------------------------------------------------------------- never-send (W4)

    def get_never_send(self) -> list:
        with self._lock:
            self._require()
            return list(self._load_never())

    def set_never_send(self, terms) -> list:
        clean = _clean_terms(terms)
        with self._lock:
            self._require()
            self._write_blob(self.root / NEVER_SEND, "never-send", "never-send", {"terms": clean})
            self._never, self._matchers = list(clean), None
        return list(clean)

    def handoff_check(self, text, units: str = "codepoint") -> dict:
        """{"ok": no hits, "hits": [{"start", "end", "term", "reason"}]} (see find_hits).
        units="utf16" gives offsets a browser can use directly. The server runs this for the
        page's check AND again on the exact text of a handoff Send (/api/chat/job)."""
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if len(text) > HANDOFF_MAX:
            raise ValueError(f"text too long to check (max {HANDOFF_MAX} characters)")
        if units not in ("codepoint", "utf16"):
            raise ValueError("units must be 'codepoint' or 'utf16'")
        with self._lock:
            self._require()
            if self._matchers is None:
                self._matchers = [(m, t) for t in self._load_never() for m in [_term_matcher(t)] if m]
            matchers = self._matchers
        hits = find_hits(text, matchers)
        if units == "utf16":
            hits = utf16_offsets(text, hits)
        return {"ok": not hits, "hits": hits}

    # -------------------------------------------------------------- internals: lock

    def _require(self):
        self._expire_if_idle()
        if self._aead is None:
            raise Locked("Marty Jr.'s history is locked")
        self._last_used = self._clock()
        return self._aead

    def _expire_if_idle(self):
        if self._aead is not None and self._clock() - self._last_used >= self.idle_seconds:
            self._drop_key()

    def _drop_key(self):
        was_open = self._aead is not None
        if self._key is not None:
            self._key[:] = bytes(len(self._key))
        self._key = self._aead = self._index = self._never = self._matchers = None
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        if was_open:
            for callback in list(self.on_lock):
                threading.Thread(target=self._run_callback, args=(callback,), daemon=True,
                                 name="jr-store-on-lock").start()

    @staticmethod
    def _run_callback(callback):
        try:
            callback()
        except Exception:
            pass                                # a failed purge must never break locking

    def _fail(self):
        with self._lock:
            self._failures.append(self._clock())

    def _arm_timer(self):
        if self._timer is not None:
            self._timer.cancel()
        delay = max(0.05, self.idle_seconds - (self._clock() - self._last_used)) + 0.01
        timer = threading.Timer(delay, self._on_timer)
        timer.daemon = True
        timer.name = "jr-store-autolock"
        self._timer = timer
        timer.start()

    def _on_timer(self):
        with self._lock:
            if self._aead is None:
                return
            self._expire_if_idle()
            if self._aead is not None:
                self._arm_timer()

    def _install(self, key, aead):
        self._key, self._aead = key, aead
        self._last_used = self._clock()
        self._notices = set()
        try:
            self._sweep_temp()
            self._index = self._load_index()
        except BaseException:
            self._drop_key()
            raise
        self.epoch = secrets.token_hex(8)
        self._arm_timer()                       # before anything else can go wrong
        self._flush_pending()

    def _flush_pending(self):
        """Write the turns held while locked, in order. Never raises. A passing failure (a
        file held open, a full disk) keeps that turn and the ones after it for the next
        unlock; a turn that can never land (not this handle's thread, a damaged thread) is
        dropped. _append skips a turn already in its thread, so a retry never duplicates."""
        pending, keep = self._pending, []
        for n, (handle, tid, turn) in enumerate(pending):
            try:
                self._append(handle, tid, turn)
            except (StoreBusy, OSError):
                keep = pending[n:]
                self._notices.add("turns_waiting")
                break
            except Exception:
                self._notices.add("turn_dropped")
        self._pending = keep

    # -------------------------------------------------------------- internals: key

    @staticmethod
    def _check_params(p: dict) -> dict:
        try:
            out = {k: int(p[k]) for k in ("iterations", "lanes", "memory_kib")}
        except (KeyError, TypeError, ValueError):
            raise StoreCorrupt("the key settings are not valid") from None
        for k, v in out.items():
            if not KDF_FLOOR[k] <= v <= KDF_CEILING[k]:
                raise StoreCorrupt("the key settings are outside the allowed range")
        if out["memory_kib"] < 8 * out["lanes"]:
            raise StoreCorrupt("the key settings are not valid")
        return out

    def _derive(self, pw: bytearray, salt: bytes, params: dict) -> bytearray:
        self.kdf_runs += 1
        key = bytearray(KEY_BYTES)
        try:
            Argon2id(salt=salt, length=KEY_BYTES, iterations=params["iterations"], lanes=params["lanes"],
                     memory_cost=params["memory_kib"]).derive_into(pw, key)
        except Exception:
            raise StoreError("the key could not be derived") from None
        return key

    @staticmethod
    def _check_aad(salt: bytes, params: dict) -> bytes:
        return _aad("keycheck", f"argon2id;{_b64(salt)};{params['iterations']};{params['lanes']};"
                                f"{params['memory_kib']}")

    def _load_keyinfo(self) -> dict:
        try:
            raw = json.loads(_read_bytes(self.root / KEYINFO).decode("utf-8"))
            if raw.get("format") != FORMAT or raw.get("kdf") != "argon2id":
                raise ValueError
            salt, check = _unb64(raw.get("salt")), _unb64(raw.get("check"))
            if len(salt) != SALT_BYTES or len(check) != NONCE_BYTES + len(CHECK_TEXT) + TAG_BYTES:
                raise ValueError
        except (OSError, ValueError, AttributeError, UnicodeDecodeError):
            raise StoreCorrupt("keyinfo.json is not valid") from None
        params = self._check_params(raw)
        return {"salt": salt, "params": params, "check": check, "check_aad": self._check_aad(salt, params)}

    def _history_exists(self) -> bool:
        if not self.root.is_dir():
            return False
        return any(name in (INDEX, NEVER_SEND) or THREAD_FILE.match(name) for name in os.listdir(self.root))

    def _setup(self, text: str) -> bool:
        if len(text) < PASSPHRASE_MIN:
            raise WeakPassphrase(f"the passphrase needs at least {PASSPHRASE_MIN} characters")
        if len(text) > PASSPHRASE_MAX:
            raise WeakPassphrase(f"the passphrase can be at most {PASSPHRASE_MAX} characters")
        if self._history_exists():
            raise StoreCorrupt("keyinfo.json is missing but encrypted history exists; "
                               "refusing to start a new key over it")
        params = dict(self._kdf_setup)
        salt = os.urandom(SALT_BYTES)
        pw = bytearray(text.encode("utf-8"))
        try:
            key = self._derive(pw, salt, params)
        finally:
            pw[:] = bytes(len(pw))
        aead = AESGCM(key)
        nonce = os.urandom(NONCE_BYTES)
        check = nonce + aead.encrypt(nonce, CHECK_TEXT, self._check_aad(salt, params))
        info = {"format": FORMAT, "kdf": "argon2id", "salt": _b64(salt), **params, "check": _b64(check)}
        with self._lock:
            if self._history_exists():          # checked again: the KDF took a moment
                key[:] = bytes(len(key))
                raise StoreCorrupt("encrypted history appeared during setup; refusing to start a new key")
            self.root.mkdir(parents=True, exist_ok=True)
            try:
                self._create_new(self.root / KEYINFO, (json.dumps(info, indent=2) + "\n").encode("ascii"))
            except BaseException:
                key[:] = bytes(len(key))
                raise
            self._key, self._aead = key, aead
            self._last_used = self._clock()
            self._notices = set()
            self._missing_found = 0
            self._index = {"threads": {}}
            try:
                self._write_index()
            except BaseException:
                self._drop_key()
                raise
            self._failures.clear()
            self.epoch = secrets.token_hex(8)
            self._arm_timer()
            self._flush_pending()
        return True

    def _create_new(self, path: pathlib.Path, data: bytes):
        """Write a file that must not exist yet, atomically: a second setup running at the same
        moment (another process) fails instead of replacing the first one's key."""
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        try:
            with open(tmp, "xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            try:
                if os.name == "nt":
                    os.rename(tmp, path)        # Windows: refuses when the target exists
                else:
                    os.link(tmp, path)          # POSIX: link refuses when the target exists
            except FileExistsError:
                raise StoreError("Jr's history was set up at the same moment elsewhere; unlock again") from None
        finally:
            if os.path.lexists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    # -------------------------------------------------------------- internals: blobs

    def _atomic_write(self, path: pathlib.Path, data: bytes):
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(6)}.tmp")
        try:
            with open(tmp, "xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            for attempt in range(REPLACE_TRIES):
                try:
                    os.replace(tmp, path)
                    return
                except PermissionError:
                    if attempt == REPLACE_TRIES - 1:
                        raise StoreBusy("a history file stayed locked by another program") from None
                    self.write_retries += 1
                    time.sleep(REPLACE_WAIT)
        finally:
            if os.path.lexists(tmp):
                try:
                    os.unlink(tmp)
                except OSError:
                    pass

    def _sweep_temp(self):
        """Temp files a crash left behind (ciphertext only, but clutter)."""
        if not self.root.is_dir():
            return
        for name in os.listdir(self.root):
            if TEMP_FILE.match(name):
                try:
                    os.unlink(self.root / name)
                except OSError:
                    pass

    def _write_blob(self, path: pathlib.Path, kind: str, ident: str, obj) -> int:
        # ensure_ascii: a lone surrogate in Jr's text becomes a \\ud800 escape instead of an
        # encode error, whose message would quote the plaintext.
        data = json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        nonce = os.urandom(NONCE_BYTES)
        blob = MAGIC + nonce + self._aead.encrypt(nonce, data, _aad(kind, ident))
        self._atomic_write(path, blob)
        return len(blob)

    def _read_blob(self, path: pathlib.Path, kind: str, ident: str):
        raw = _read_bytes(path)
        if len(raw) < len(MAGIC) + NONCE_BYTES + TAG_BYTES or raw[:3] != MAGIC[:3]:
            raise StoreCorrupt("a history file is damaged or was altered")
        if raw[:4] != MAGIC:
            raise StoreCorrupt("a history file has an unknown format version")
        try:
            plain = self._aead.decrypt(raw[4:4 + NONCE_BYTES], raw[4 + NONCE_BYTES:], _aad(kind, ident))
            return json.loads(plain.decode("utf-8"))
        except (InvalidTag, ValueError, UnicodeDecodeError):
            raise StoreCorrupt("a history file is damaged or was altered") from None

    def _write_index(self):
        self._write_blob(self.root / INDEX, "index", "index", self._index)

    def _write_thread(self, thread: dict) -> int:
        return self._write_blob(self.root / f"{thread['id']}.bin", "thread", thread["id"], thread)

    def _read_thread(self, tid: str, handle=None) -> dict:
        try:
            t = self._read_blob(self.root / f"{tid}.bin", "thread", tid)
        except FileNotFoundError:
            raise StoreCorrupt("a history file is missing") from None
        if (not isinstance(t, dict) or t.get("id") != tid or not isinstance(t.get("turns"), list)
                or not isinstance(t.get("handle"), str)):
            raise StoreCorrupt("a history file is damaged or was altered")
        if handle is not None and t["handle"] != handle:
            raise StoreCorrupt("a history file does not belong to this conversation")
        return t

    @staticmethod
    def _view(t: dict) -> dict:
        return {"id": t["id"], "title": t.get("title") or "", "created": t.get("created"),
                "updated": t.get("updated"), "turns": copy.deepcopy(t["turns"])}

    def _load_index(self) -> dict:
        """Read the index, then reconcile it with the thread files: add a thread written just
        before a crash, move an entry whose file is gone to index["missing"] (counted, never
        dropped silently; a file that comes back is listed again), and re-read a thread whose
        file size differs from the one recorded (an append whose index write was lost). The
        index only repeats facts the authenticated thread files hold, so a missing one is
        rebuilt, and a damaged one is moved aside to index.bin.damaged and rebuilt, with a
        notice."""
        path = self.root / INDEX
        missing = not path.exists()
        index = None
        if not missing:
            try:
                index = self._read_blob(path, "index", "index")
                ok = isinstance(index, dict) and isinstance(index.get("threads"), dict) and all(
                    isinstance(e, dict) and isinstance(e.get("handle"), str) and isinstance(e.get("turns"), int)
                    and ID_RE.match(tid) for tid, e in index["threads"].items())
                gone = index.get("missing", {}) if isinstance(index, dict) else None
                ok = ok and isinstance(gone, dict) and all(
                    isinstance(e, dict) and isinstance(e.get("handle"), str) and ID_RE.match(tid)
                    for tid, e in gone.items())
                if not ok:
                    raise StoreCorrupt("the history index is damaged or was altered")
            except StoreCorrupt:
                try:
                    os.replace(path, self.root / (INDEX + ".damaged"))
                except OSError:
                    raise StoreCorrupt("the history index is damaged and could not be set aside") from None
                self._notices.add("index_rebuilt")
                index, missing = None, True
        if index is None:
            index = {"threads": {}}
        threads, gone = index["threads"], index.setdefault("missing", {})
        sizes = {}
        if self.root.is_dir():
            for name in os.listdir(self.root):
                m = THREAD_FILE.match(name)
                if m:
                    try:
                        sizes[m.group(1)] = os.stat(self.root / name).st_size
                    except OSError:
                        pass
        changed = missing
        for tid in sorted(sizes):
            entry = threads.get(tid)
            if entry is not None and entry.get("size") == sizes[tid]:
                continue
            try:
                t = self._read_thread(tid)
            except StoreError:
                self._notices.add("unreadable_threads")
                continue                        # a damaged file stays on disk; get_thread refuses it
            threads[tid] = {"handle": t["handle"], "title": t.get("title") or "", "created": t.get("created"),
                            "updated": t.get("updated"), "turns": len(t["turns"]), "size": sizes[tid]}
            gone.pop(tid, None)                 # a file that came back (restored) is listed again
            changed = True
        found = 0
        for tid in sorted(set(threads) - set(sizes)):
            entry = threads.pop(tid)            # its file is gone: counted, never dropped silently
            gone[tid] = {"handle": entry["handle"], "title": entry.get("title") or "", "since": jr_lane._now()}
            found += 1
            changed = True
        self._missing_found = found
        self._index = index
        if changed:
            self._write_index()
        return index

    def _append(self, handle, tid, turn):
        if not isinstance(tid, str) or not ID_RE.match(tid):
            raise KeyError("no such thread")
        entry = self._index["threads"].get(tid)
        if entry is None or entry["handle"] != handle:
            raise KeyError("no such thread")
        t = self._read_thread(tid, handle)
        size = None
        if turn.get("id") is None or not any(x.get("id") == turn["id"] for x in t["turns"]):
            t["turns"].append(copy.deepcopy(turn))
            if not t.get("title"):
                t["title"] = " ".join((turn.get("user") or "").split())[:60] or "Conversation"
            t["updated"] = jr_lane._now()
            size = self._write_thread(t)
        before = dict(entry)
        entry.update(title=t["title"], updated=t["updated"], turns=len(t["turns"]),
                     size=size if size is not None else entry.get("size"))
        try:
            self._write_index()
        except Exception:
            entry.clear()
            entry.update(before)                # the thread file is right; the index catches up at unlock
            raise

    def _load_never(self) -> list:
        if self._never is None:
            path = self.root / NEVER_SEND
            if not path.exists():
                self._never = []
            else:
                data = self._read_blob(path, "never-send", "never-send")
                terms = data.get("terms") if isinstance(data, dict) else None
                if not isinstance(terms, list) or not all(isinstance(t, str) for t in terms):
                    raise StoreCorrupt("the never-send list is damaged or was altered")
                self._never = terms
        return self._never
