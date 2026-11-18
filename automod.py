"""Auto-moderation helpers: rule validation and bounded regex evaluation.

Regex rules are written by admins but evaluated against text typed by anyone.
Python's re module holds the GIL for the whole match, so a thread cannot keep a
catastrophic pattern from freezing the event loop (measured: a thread running
(a+)+$ on 27 'a' characters plus one 'b' froze the loop for the whole 6 seconds).
The limits are therefore:

  1. validate_automod_config() refuses patterns that are long, do not compile,
     or repeat a group that itself contains an unbounded repeat. This is a
     heuristic; it does not catch every catastrophic pattern (for example
     a*a*a*a*b, or an alternation such as (a|aa)+$).
  2. Text handed to a regex is cut to REGEX_TEXT_LIMIT characters. This bounds
     polynomial patterns only; 2000 characters is still plenty for an
     exponential one.
  3. RegexRunner evaluates patterns in a separate worker process with a
     hard time budget. When the budget runs out the worker is killed and
     restarted, so the portal process never runs the pattern itself. The check
     then fails closed: RegexCheckError is raised, the message that was being
     checked is rejected for its author (see apply_automod in server.py), and
     the pattern is tried again for the next message, so a slow pattern can
     never be used to let content through. Timeouts are counted per pattern
     (RegexRunner.timeouts_in_last_hour) for the admin rule list. The callers
     rate limit a member's messages before they reach the rules, which bounds
     the worker time one member can use.
"""

import asyncio
import json
import logging
import re
import sys
from collections import deque
from functools import lru_cache
from time import monotonic

logger = logging.getLogger("portal.automod")

REGEX_MAX_PATTERN = 500        # characters per pattern
REGEX_MAX_PATTERNS = 100       # patterns per word_filter rule in regex mode
REGEX_TEXT_LIMIT = 2000        # characters of a message handed to a regex
REGEX_BUDGET_SECONDS = 0.25    # hard limit for one pattern against one text
SLOW_PATTERN_WINDOW_SECONDS = 3600.0   # timeouts are counted over this long for the admin list

MATCH_MODES = ("contains", "exact", "regex")

_QUANT_RE = re.compile(r"\{(\d*)(,(\d*))?\}")


def _unbounded_quantifier(pattern: str, i: int):
    """Return (end, unbounded) if pattern[i] starts a quantifier, else None."""
    if i >= len(pattern):
        return None
    c = pattern[i]
    if c in "*+":
        return i + 1, True
    if c == "?":
        return i + 1, False
    if c == "{":
        m = _QUANT_RE.match(pattern, i)
        # {n}, {n,}, {n,m}, {,m} and {,}; Python reads {,} as {0,} (unbounded).
        # A bare {} or { ,} is literal text, not a quantifier.
        if m and (m.group(1) or m.group(2)):
            return m.end(), bool(m.group(2)) and not m.group(3)
    return None


def nested_quantifier(pattern: str) -> bool:
    """Heuristic: True if a group with an unbounded repeat is itself repeated without bound.

    Catches (a+)+, (a*)*, (\\w+\\s?)+, (?:a+){2,}. It does not catch every
    catastrophic pattern; see the module docstring.
    """
    stack = [False]   # per open group: does it contain an unbounded repeat
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pattern[j] == "^":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 2 if pattern[j] == "\\" else 1
            i = j + 1
            continue
        if c == "(":
            if pattern.startswith("(?#", i):
                end = pattern.find(")", i)
                i = n if end < 0 else end + 1
                continue
            stack.append(False)
            i += 1
            continue
        if c == ")":
            inner = stack.pop() if len(stack) > 1 else False
            q = _unbounded_quantifier(pattern, i + 1)
            if q is not None and q[1]:
                if inner:
                    return True
                stack[-1] = True
            elif inner:
                stack[-1] = True
            i = i + 1 if q is None else q[0]
            if q is not None and i < n and pattern[i] in "?+":
                i += 1   # lazy / possessive marker
            continue
        q = _unbounded_quantifier(pattern, i)
        if q is not None:
            if q[1]:
                stack[-1] = True
            i = q[0]
            if i < n and pattern[i] in "?+":
                i += 1
            continue
        i += 1
    return False


@lru_cache(maxsize=1024)
def regex_problem(pattern) -> str | None:
    """Reason a pattern is refused, or None if it is acceptable."""
    if not isinstance(pattern, str):
        return "pattern must be a string"
    if not pattern:
        return "pattern is empty"
    if len(pattern) > REGEX_MAX_PATTERN:
        return f"pattern is longer than {REGEX_MAX_PATTERN} characters"
    try:
        re.compile(pattern, re.IGNORECASE)
    except re.error as e:
        return f"does not compile: {e}"
    except (RecursionError, OverflowError):
        return "pattern is too complex"
    if nested_quantifier(pattern):
        return "repeats a group that already contains an unbounded repeat (nested quantifier)"
    return None


def unenforced_reason(rule_type: str, config) -> str | None:
    """Why a stored rule is not (fully) enforced at run time, or None.

    Mirrors what chat does when it meets a stored regex pattern that now fails
    regex_problem(): that pattern is skipped, the rule's other patterns still run.
    A spam_filter rule is stored but chat has no check for it.
    """
    if rule_type == "spam_filter":
        return "spam_filter rules are stored but never applied to messages"
    if rule_type != "word_filter" or not isinstance(config, dict):
        return None
    if config.get("match_mode", "contains") != "regex":
        return None
    words = config.get("words", [])
    if not isinstance(words, list):
        return None
    bad = [(w, regex_problem(w)) for w in words if isinstance(w, str)]
    bad = [(w, p) for w, p in bad if p]
    if not bad:
        return None
    w, problem = bad[0]
    shown = w if len(w) <= 60 else w[:60] + "..."
    skipped = "pattern is" if len(bad) == 1 else f"{len(bad)} patterns are"
    return f"{skipped} skipped, first: '{shown}': {problem}"


def slow_pattern_timeouts(runner, rule_type: str, config) -> int:
    """Budget overruns in the last hour of the patterns of a regex word_filter rule (0 for any other rule)."""
    if rule_type != "word_filter" or not isinstance(config, dict):
        return 0
    if config.get("match_mode", "contains") != "regex":
        return 0
    words = config.get("words", [])
    if not isinstance(words, list):
        return 0
    return sum(runner.timeouts_in_last_hour(w) for w in words if isinstance(w, str))


def validate_automod_config(rule_type: str, config) -> str | None:
    """Return an error message for an unacceptable rule config, or None."""
    if not isinstance(config, dict):
        return "config must be an object"
    if rule_type != "word_filter":
        return None
    words = config.get("words", [])
    if not isinstance(words, list) or not all(isinstance(w, str) for w in words):
        return "words must be a list of strings"
    mode = config.get("match_mode", "contains")
    if mode not in MATCH_MODES:
        return f"match_mode must be one of: {', '.join(MATCH_MODES)}"
    if mode == "regex":
        if len(words) > REGEX_MAX_PATTERNS:
            return f"at most {REGEX_MAX_PATTERNS} patterns per regex rule"
        for w in words:
            problem = regex_problem(w)
            if problem:
                shown = w if len(w) <= 60 else w[:60] + "..."
                return f"Invalid regex pattern '{shown}': {problem}"
    return None


# Source of the worker process: reads one JSON request per line, answers one per line.
_WORKER_SOURCE = r'''
import sys, re, json
from functools import lru_cache

@lru_cache(maxsize=256)
def compiled(p):
    try:
        return re.compile(p, re.IGNORECASE)
    except Exception:
        return None

for line in sys.stdin:
    hit = False
    try:
        req = json.loads(line)
        rx = compiled(req["p"])
        hit = bool(rx and rx.search(req["t"]))
    except Exception:
        pass
    sys.stdout.write(json.dumps({"hit": hit}) + "\n")
    sys.stdout.flush()
'''


class RegexCheckError(Exception):
    """A regex rule could not be evaluated for a message (budget overrun or worker failure).

    The message must be treated as not checked, which means rejected.
    timed_out is True when the pattern overran its time budget.
    """

    def __init__(self, pattern: str, timed_out: bool):
        super().__init__("regex check timed out" if timed_out else "regex worker failed")
        self.pattern = pattern
        self.timed_out = timed_out


_MAX_TRACKED_PATTERNS = 512
_MAX_TIMEOUTS_PER_PATTERN = 1000
_LOG_INTERVAL_SECONDS = 60.0


class RegexRunner:
    """Runs regex searches in a worker process that is killed when it overruns its budget."""

    def __init__(self, budget: float = REGEX_BUDGET_SECONDS):
        self.budget = budget
        self._proc = None
        self._lock = asyncio.Lock()
        self._timeouts: dict[str, deque] = {}     # pattern -> monotonic times of its budget overruns
        self._last_logged: dict[str, float] = {}
        self.restarts = 0

    async def _start(self):
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable, "-I", "-S", "-c", _WORKER_SOURCE,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )

    async def _kill(self):
        proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        try:
            await proc.wait()
        except Exception:
            pass

    async def _roundtrip(self, pattern: str, text: str) -> bool:
        line = json.dumps({"p": pattern, "t": text}) + "\n"
        self._proc.stdin.write(line.encode("ascii"))
        await self._proc.stdin.drain()
        reply = await self._proc.stdout.readline()
        if not reply:
            raise ConnectionError("regex worker exited")
        return bool(json.loads(reply).get("hit"))

    def _note_timeout(self, pattern: str) -> None:
        now = monotonic()
        times = self._timeouts.get(pattern)
        if times is None:
            if len(self._timeouts) >= _MAX_TRACKED_PATTERNS:
                self._prune(now)
            if len(self._timeouts) >= _MAX_TRACKED_PATTERNS:
                self._timeouts.pop(next(iter(self._timeouts)))
            times = self._timeouts[pattern] = deque(maxlen=_MAX_TIMEOUTS_PER_PATTERN)
        times.append(now)

    def _prune(self, now: float) -> None:
        cutoff = now - SLOW_PATTERN_WINDOW_SECONDS
        for p in [p for p, t in self._timeouts.items() if not t or t[-1] < cutoff]:
            del self._timeouts[p]
            self._last_logged.pop(p, None)

    def timeouts_in_last_hour(self, pattern: str) -> int:
        """How many times this pattern overran its budget in the last hour."""
        times = self._timeouts.get(pattern)
        if not times:
            return 0
        cutoff = monotonic() - SLOW_PATTERN_WINDOW_SECONDS
        return sum(1 for t in times if t >= cutoff)

    def _log_timeout(self, pattern: str) -> None:
        now = monotonic()
        if now - self._last_logged.get(pattern, -_LOG_INTERVAL_SECONDS) < _LOG_INTERVAL_SECONDS:
            return
        if len(self._last_logged) >= _MAX_TRACKED_PATTERNS:
            self._last_logged.clear()
        self._last_logged[pattern] = now
        shown = pattern if len(pattern) <= 80 else pattern[:80] + "..."
        logger.warning("automod regex %r exceeded %.2fs; worker restarted, the message was rejected "
                       "(logged once a minute per pattern)", shown, self.budget)

    async def search(self, pattern: str, text: str) -> bool:
        """True if pattern matches text (case-insensitive).

        Raises RegexCheckError when the pattern overruns the budget or the worker
        fails twice: the caller must then treat the text as not checked.
        """
        text = text[:REGEX_TEXT_LIMIT]
        async with self._lock:
            for attempt in (1, 2):
                try:
                    if self._proc is None or self._proc.returncode is not None:
                        await self._kill()
                        await self._start()
                    return await asyncio.wait_for(self._roundtrip(pattern, text), self.budget)
                except asyncio.CancelledError:
                    # The request may already be written; an unread reply would be
                    # taken for the next pattern's answer, so drop the worker.
                    await self._kill()
                    raise
                except asyncio.TimeoutError:
                    await self._kill()
                    self.restarts += 1
                    self._note_timeout(pattern)
                    self._log_timeout(pattern)
                    raise RegexCheckError(pattern, True) from None
                except (ConnectionError, BrokenPipeError, OSError, ValueError) as e:
                    await self._kill()
                    if attempt == 2:
                        logger.warning("automod regex worker failed: %s", e)
                        raise RegexCheckError(pattern, False) from None
        raise RegexCheckError(pattern, False)

    async def close(self):
        async with self._lock:
            await self._kill()
