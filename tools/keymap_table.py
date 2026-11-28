#!/usr/bin/env python3
"""Prints KEYMAP_KEYSYMS, the data block of rbrowser_unit/session.py: the keysym noVNC's keysymdef.js lookup() gives for every code
point above Latin-1 in the supervisor's keyboard table. Run it when keymap_codepoint_units() or the vendored noVNC changes, and paste
the output between `KEYMAP_KEYSYMS = {` and `}` (tests/test_rbrowser_supervisor.py checks the pasted values against the JS file).

    python3 tools/keymap_table.py
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
KEYSYMDEF = ROOT / "static" / "vendor" / "novnc" / "core" / "input" / "keysymdef.js"


def novnc_lookup(text):
    """The JavaScript lookup(): Latin-1 as itself, the table, else 0x01000000 | code point."""
    table = {int(a, 16): int(b, 16) for a, b in re.findall(r"^\s*(0x[0-9a-fA-F]+):\s*(0x[0-9a-fA-F]+),", text, re.M)}

    def lookup(u):
        if 0x20 <= u <= 0xFF:
            return u
        return table.get(u, 0x01000000 | u)
    return lookup


def main():
    from rbrowser_unit import session as S
    lookup = novnc_lookup(KEYSYMDEF.read_text(encoding="utf-8"))
    cps = sorted({cp for u in S.keymap_codepoint_units() for cp in u if cp > 0xFF})
    for cp in cps:
        print(f"    0x{cp:04X}: 0x{lookup(cp):04X},")


main()
