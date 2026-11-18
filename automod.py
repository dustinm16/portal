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
     restarted, so the portal process never runs the pattern itself. A pattern
     that times out is skipped (treated as no match) for a cool-down period so
     one bad pattern cannot keep the worker busy.
"""

import asyncio
import json
import logging
import re
import sys
from functools import lru_cache
from time import monotonic

logger = logging.getLogger("portal.automod")

REGEX_MAX_PATTERN = 500        # characters per pattern
REGEX_MAX_PATTERNS = 100       # patterns per word_filter rule in regex mode
REGEX_TEXT_LIMIT = 2000        # characters of a message handed to a regex
REGEX_BUDGET_SECONDS = 0.25    # hard limit for one pattern against one text
REGEX_COOLDOWN_SECONDS = 60.0  # a pattern that timed out is skipped this long

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
    """
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


class RegexRunner:
    """Runs regex searches in a worker process that is killed when it overruns its budget."""

    def __init__(self, budget: float = REGEX_BUDGET_SECONDS, cooldown: float = REGEX_COOLDOWN_SECONDS):
        self.budget = budget
        self.cooldown = cooldown
        self._proc = None
        self._lock = asyncio.Lock()
        self._tripped: dict[str, float] = {}
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

    async def search(self, pattern: str, text: str) -> bool:
        """True if pattern matches text (case-insensitive). False when it overruns the budget."""
        text = text[:REGEX_TEXT_LIMIT]
        now = monotonic()
        until = self._tripped.get(pattern)
        if until is not None:
            if until > now:
                return False
            del self._tripped[pattern]
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
                    if len(self._tripped) > 256:
                        self._tripped = {p: u for p, u in self._tripped.items() if u > now}
                    self._tripped[pattern] = monotonic() + self.cooldown
                    shown = pattern if len(pattern) <= 80 else pattern[:80] + "..."
                    logger.warning("automod regex %r exceeded %.2fs; worker restarted, pattern skipped for %ds",
                                   shown, self.budget, int(self.cooldown))
                    return False
                except (ConnectionError, BrokenPipeError, OSError, ValueError) as e:
                    await self._kill()
                    if attempt == 2:
                        logger.warning("automod regex worker failed: %s", e)
                        return False
        return False

    async def close(self):
        async with self._lock:
            await self._kill()
