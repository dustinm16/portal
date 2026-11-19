"""Message search: the query parser and the per-message index flags.

Pure functions, no database and no server state, so the rules can be tested on
their own. The server calls parse_search_query for every request; the
database layer calls message_flags whenever it writes a search index row.

Query syntax (whitespace separated, operators are case-insensitive):

    from:name   -from:name    author, by account name or nickname
    in:channel  -in:channel   channel by name (a leading # is ignored)
    has:link | has:file | has:image
    is:pinned
    before:YYYY-MM-DD   after:YYYY-MM-DD    UTC dates
    "some words"              a phrase
    anything else             words that must all appear

A token is an operator only when it is letters, a colon and a value, so times
such as 12:30 and addresses such as https://example.com are searched as text.
An unknown operator, an unknown value or a bad date raises SearchQueryError;
put the text in double quotes to search for it literally.
"""

import re
from dataclasses import dataclass, field
from datetime import date
from typing import Optional

MAX_QUERY_LENGTH = 200
MAX_OPERATORS = 10
MAX_VALUE_LENGTH = 64
# An operator-only query returns at most this many results in total.
OPERATOR_ONLY_CAP = 200

OPERATORS = ("from", "in", "has", "is", "before", "after")
HAS_VALUES = ("link", "file", "image")
IS_VALUES = ("pinned",)
_NEGATABLE = frozenset(("from", "in"))
_SINGLE = frozenset(("before", "after"))

# Same pattern the chat page uses to turn text into a link.
_LINK_RE = re.compile(r"https?://[^\s<]+")
_TOKEN_RE = re.compile(r'-?[A-Za-z]+:\S*|"[^"]*"|\S+')
_OPERATOR_TOKEN_RE = re.compile(r'^(-?)([A-Za-z]+):(.*)$', re.S)
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Characters that mean something in an FTS5 expression outside quotes; they
# are blanked out of free text exactly as the search always did.
_FTS_SPECIAL = re.compile(r'["*():\-^]')


class SearchQueryError(ValueError):
    """The query cannot be parsed; the message is meant for the person who typed it."""


@dataclass
class ParsedSearch:
    phrases: list = field(default_factory=list)      # each a list of words
    from_users: list = field(default_factory=list)
    not_from_users: list = field(default_factory=list)
    in_channels: list = field(default_factory=list)
    not_in_channels: list = field(default_factory=list)
    has: list = field(default_factory=list)
    pinned: bool = False
    before: Optional[str] = None       # YYYY-MM-DD: messages created before that day starts (UTC)
    after: Optional[str] = None        # YYYY-MM-DD: messages created from the start of that day (UTC)

    @property
    def words(self) -> list:
        """Every free-text word, for highlighting."""
        return [w for p in self.phrases for w in p]

    @property
    def operator_only(self) -> bool:
        return not self.phrases

    @property
    def has_operators(self) -> bool:
        return bool(self.from_users or self.not_from_users or self.in_channels
                    or self.not_in_channels or self.has or self.pinned
                    or self.before or self.after)

    @property
    def fts_expr(self) -> str:
        """FTS5 expression: every word or phrase must be present."""
        return " ".join('"%s"' % " ".join(p) for p in self.phrases)


def _words(text: str) -> list:
    return _FTS_SPECIAL.sub(" ", text).split()


def _check_date(name: str, value: str) -> str:
    if not _DATE_RE.match(value):
        raise SearchQueryError(f"{name}: needs a date written YYYY-MM-DD, for example {name}:2026-11-01")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise SearchQueryError(f"{name}:{value} is not a real date")
    return value


def _add_operator(p: ParsedSearch, name: str, value: str, negated: bool) -> None:
    name = name.lower()
    if name not in OPERATORS:
        raise SearchQueryError(
            f"Unknown search operator '{name}:'. Operators are "
            + ", ".join(o + ":" for o in OPERATORS)
            + '. To search for the text itself, put it in double quotes.')
    if negated and name not in _NEGATABLE:
        raise SearchQueryError(f"'-{name}:' is not supported; only -from: and -in: can be negated")
    value = value.strip()
    if not value:
        raise SearchQueryError(f"{name}: needs a value")
    if len(value) > MAX_VALUE_LENGTH:
        raise SearchQueryError(f"The value after {name}: is too long")
    if name == "from":
        (p.not_from_users if negated else p.from_users).append(value)
    elif name == "in":
        channel = value.lstrip("#").lower()
        if not channel:
            raise SearchQueryError("in: needs a channel name")
        (p.not_in_channels if negated else p.in_channels).append(channel)
    elif name == "has":
        v = value.lower()
        if v not in HAS_VALUES:
            raise SearchQueryError(f"Unknown has: value '{value}'. Use has:link, has:file or has:image")
        if v not in p.has:
            p.has.append(v)
    elif name == "is":
        v = value.lower()
        if v not in IS_VALUES:
            raise SearchQueryError(f"Unknown is: value '{value}'. Use is:pinned")
        p.pinned = True
    else:
        if getattr(p, name) is not None:
            raise SearchQueryError(f"{name}: can be given only once")
        setattr(p, name, _check_date(name, value))


def parse_search_query(q: str, *, from_=None, has=None, before=None, after=None) -> ParsedSearch:
    """Parse a search query. The keyword arguments carry the separate request
    parameters of the older API (from=, has=, before=, after=) through the same
    validation. Raises SearchQueryError with a message fit for display."""
    p = ParsedSearch()
    count = 0
    for tok in _TOKEN_RE.findall(q or ""):
        m = _OPERATOR_TOKEN_RE.match(tok)
        if m and not tok.startswith('"'):
            neg, name, value = m.group(1) == "-", m.group(2), m.group(3)
            known = name.lower() in OPERATORS
            # Unknown names count as operators only with a value that is not
            # the start of an address (https://...), so "Note:" and URLs stay text.
            if known or (value and not value.startswith("//")):
                count += 1
                if count > MAX_OPERATORS:
                    raise SearchQueryError(f"Too many operators (at most {MAX_OPERATORS})")
                _add_operator(p, name, value, neg)
                continue
        if tok.startswith('"') and tok.endswith('"') and len(tok) >= 2:
            words = _words(tok[1:-1])
            if words:
                p.phrases.append(words)
            continue
        for word in _words(tok):
            p.phrases.append([word])
    for name, value in (("from", from_), ("has", has), ("before", before), ("after", after)):
        if value is None or value == "":
            continue
        count += 1
        if count > MAX_OPERATORS:
            raise SearchQueryError(f"Too many operators (at most {MAX_OPERATORS})")
        _add_operator(p, name, str(value), False)
    return p


def message_flags(plaintext, image_url=None, attachment_url=None, attachment_type=None) -> tuple:
    """(has_image, has_file, has_link) for one message, as 0/1 integers.

    An image is an image_url or an attachment of an image type; a file is any
    other attachment; a link is an http(s) address in the text. This is the one
    place the three are decided, for new messages, edits, rebuilds and the
    backfill alike."""
    is_image_attachment = bool(attachment_url) and (attachment_type or "").lower().startswith("image/")
    has_image = 1 if (image_url or is_image_attachment) else 0
    has_file = 1 if (attachment_url and not is_image_attachment) else 0
    has_link = 1 if (plaintext and _LINK_RE.search(plaintext)) else 0
    return has_image, has_file, has_link
