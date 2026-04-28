"""Shared encoding-safe character helpers for terminal reporters.

On Windows terminals whose console encoding is cp1252 (still the default on
some setups), writing characters like '═', '→', '✓', '✗' or em-dash '—'
raises UnicodeEncodeError or shows up as gibberish / replacement chars.

There are three distinct Windows scenarios we have to cope with:

1. **TTY on Windows** — Python writes to the console directly.  We switch the
   console code page to UTF-8 (65001) via ``SetConsoleOutputCP`` so the glyphs
   render cleanly. ``reconfigure`` on ``sys.stdout`` pairs with that.

2. **Piped / redirected on Windows** (``python -m taintly | Out-File``,
   ``... > out.txt``, piping into another PowerShell cmdlet) — PowerShell
   reads the pipe's bytes through ``[Console]::OutputEncoding`` (usually
   cp1252) and re-encodes via ``Out-File``'s default (UTF-16LE on PS 5.1,
   UTF-8 no-BOM on PS 7).  Reconfiguring our stdout to UTF-8 does not help
   here: PowerShell will decode each UTF-8 byte as cp1252 and write mojibake
   into the file.  We cannot control the consumer, so we force ASCII output
   for the whole process.

3. **Explicit override** via ``CICD_AUDIT_ASCII=1`` — lets anyone on a weird
   terminal or unusual pipeline force ASCII without auto-detection.

Each helper here returns the pretty Unicode glyph when the detected stdout
encoding can represent it and ASCII emission has not been forced; otherwise
it falls back to a plain ASCII equivalent.

Call :func:`ensure_utf8_stdout` once at CLI start-up.  It combines the
console-code-page switch (case 1), the stdout/stderr reconfigure, and the
"force ASCII when redirected on Windows" detection (case 2).
"""

from __future__ import annotations

import os
import sys

# Module-level flag, set by ensure_utf8_stdout().  The per-char helpers below
# consult it rather than re-checking os.name / isatty on every call.
_ascii_only: bool = False


def _detect_force_ascii() -> bool:
    """Return True if we must emit pure ASCII regardless of stdout encoding.

    Triggers:
    - ``CICD_AUDIT_ASCII`` env var is set to a truthy value.
    - On Windows, stdout is not a TTY (redirected to file, piped into another
      process, or captured by a harness).  PowerShell / cmd re-decode the
      pipe bytes through the console code page, so UTF-8 output we write
      becomes cp1252 mojibake in the consumer's file.
    """
    override = os.environ.get("CICD_AUDIT_ASCII", "").strip().lower()
    if override and override not in ("0", "false", "no"):
        return True
    if os.name == "nt":
        try:
            isatty = sys.stdout.isatty()
        except (AttributeError, ValueError):
            # Stream detached / closed — treat as non-interactive.
            return True
        if not isatty:
            return True
    return False


def _can_encode(ch: str) -> bool:
    """Return True iff ``ch`` can be safely written to stdout.

    Short-circuits to False when ASCII-only mode has been engaged, so Windows
    redirection scenarios use the ASCII fallback characters without doing a
    per-call encode-probe.
    """
    if _ascii_only:
        return False
    encoding = getattr(sys.stdout, "encoding", None) or "ascii"
    try:
        ch.encode(encoding)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def sep_char() -> str:
    """Box-drawing double-horizontal or ASCII '=' fallback."""
    return "═" if _can_encode("═") else "="


def check_char() -> str:
    """Heavy check mark or 'OK' fallback."""
    return "✓" if _can_encode("✓") else "OK"


def cross_char() -> str:
    """Heavy ballot X or 'X' fallback."""
    return "✗" if _can_encode("✗") else "X"


def arrow_char() -> str:
    """Right arrow or '->' fallback."""
    return "→" if _can_encode("→") else "->"


def em_dash_char() -> str:
    """Em-dash or '-' fallback."""
    return "—" if _can_encode("—") else "-"


def bullet_char() -> str:
    """Bullet or '*' fallback."""
    return "•" if _can_encode("•") else "*"


def _set_windows_console_utf8() -> None:
    """Switch the Windows console code page to UTF-8 (65001) via ctypes.

    Non-fatal on failure.  Has no effect off Windows, when stdout is not a
    console, or when ``ctypes`` / ``windll`` is unavailable.
    """
    if os.name != "nt":
        return
    try:
        import ctypes  # stdlib; only used on Windows
    except ImportError:
        return
    windll = getattr(ctypes, "windll", None)
    if windll is None:
        return
    try:
        # 65001 = CP_UTF8. Affects console for this process only.
        windll.kernel32.SetConsoleOutputCP(65001)
        windll.kernel32.SetConsoleCP(65001)
    except (OSError, AttributeError):
        pass


def ensure_utf8_stdout() -> None:
    """Prepare stdout/stderr for Unicode output, or force ASCII if we can't.

    Three responsibilities:
    1. On Windows consoles, switch the code page to UTF-8 so glyphs render.
    2. Reconfigure Python's stdout/stderr to UTF-8 with ``errors="replace"``
       so writes never crash the process.
    3. Engage module-level ASCII-only mode when we detect a scenario where
       Python-side UTF-8 would arrive at a consumer (PowerShell pipe, file
       redirection) that re-decodes under a different encoding.

    Idempotent; safe to call more than once.
    """
    global _ascii_only
    _ascii_only = _detect_force_ascii()

    if not _ascii_only:
        _set_windows_console_utf8()

    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, LookupError):
            # Stream already closed, detached, or encoding not supported —
            # fall back to the per-char helpers above.
            pass


def force_ascii(enabled: bool = True) -> None:
    """Manually engage or release ASCII-only mode (useful for tests)."""
    global _ascii_only
    _ascii_only = enabled


# ---------------------------------------------------------------------------
# Output transliteration
# ---------------------------------------------------------------------------
#
# The helpers above (``sep_char``, ``em_dash_char``, ...) only cover the
# decorative glyphs the reporter itself emits.  They do NOT cover non-ASCII
# characters that arrive through user / rule data: an author writing a rule
# description like "force-pushed to point at malicious code — a technique..."
# embeds a U+2014 em-dash that flows straight through the text reporter into
# the saved file.  On Windows PowerShell the UTF-8 bytes of that em-dash are
# re-decoded through cp1252 on the way to ``Out-File``, surfacing as the
# classic "â€"" mojibake.
#
# ``to_ascii`` provides a final "flatten everything to 7-bit ASCII" pass for
# text-shaped reports.  It maps the typography glyphs rule authors actually
# use (em / en dashes, smart quotes, ellipses, bullets, arrows, check marks,
# box-drawing) to safe ASCII equivalents and replaces anything else with
# ``'?'`` so the output never contains a byte above 0x7F.

# Characters explicitly mapped to meaningful ASCII replacements. Anything
# non-ASCII not in this table falls through to ``?`` below — preferring
# safety (no mojibake) over fidelity (preserving obscure glyphs).
_ASCII_MAP = {
    # --- Dashes / minus-style ---------------------------------------------
    "\u2010": "-",  # HYPHEN
    "\u2011": "-",  # NON-BREAKING HYPHEN
    "\u2012": "-",  # FIGURE DASH
    "\u2013": "-",  # EN DASH
    "\u2014": "-",  # EM DASH
    "\u2015": "-",  # HORIZONTAL BAR
    "\u2212": "-",  # MINUS SIGN
    # --- Quotes -----------------------------------------------------------
    "\u2018": "'",  # LEFT SINGLE QUOTATION MARK
    "\u2019": "'",  # RIGHT SINGLE QUOTATION MARK
    "\u201a": "'",  # SINGLE LOW-9 QUOTATION MARK
    "\u201b": "'",  # SINGLE HIGH-REVERSED-9 QUOTATION MARK
    "\u201c": '"',  # LEFT DOUBLE QUOTATION MARK
    "\u201d": '"',  # RIGHT DOUBLE QUOTATION MARK
    "\u201e": '"',  # DOUBLE LOW-9 QUOTATION MARK
    "\u00ab": '"',  # LEFT-POINTING DOUBLE ANGLE QUOTATION
    "\u00bb": '"',  # RIGHT-POINTING DOUBLE ANGLE QUOTATION
    # --- Punctuation / spacing -------------------------------------------
    "\u2026": "...",  # HORIZONTAL ELLIPSIS
    "\u00a0": " ",  # NO-BREAK SPACE
    "\u202f": " ",  # NARROW NO-BREAK SPACE
    "\u2009": " ",  # THIN SPACE
    "\u200a": " ",  # HAIR SPACE
    "\u2003": " ",  # EM SPACE
    "\u2002": " ",  # EN SPACE
    "\u2022": "*",  # BULLET
    "\u00b7": "*",  # MIDDLE DOT
    "\u2023": ">",  # TRIANGULAR BULLET
    "\u25b8": ">",  # BLACK RIGHT-POINTING SMALL TRIANGLE
    # --- Arrows / status glyphs ------------------------------------------
    "\u2190": "<-",  # LEFTWARDS ARROW
    "\u2192": "->",  # RIGHTWARDS ARROW
    "\u2713": "OK",  # CHECK MARK
    "\u2717": "X",  # BALLOT X
    "\u2714": "OK",  # HEAVY CHECK MARK
    "\u2718": "X",  # HEAVY BALLOT X
    # --- Box-drawing ------------------------------------------------------
    "\u2500": "-",
    "\u2501": "-",
    "\u2502": "|",
    "\u2503": "|",
    "\u2550": "=",
    "\u2551": "|",
    "\u250c": "+",
    "\u2510": "+",
    "\u2514": "+",
    "\u2518": "+",
    "\u251c": "+",
    "\u2524": "+",
    "\u252c": "+",
    "\u2534": "+",
    "\u253c": "+",
}


def to_ascii(s: str) -> str:
    """Flatten ``s`` to 7-bit ASCII, transliterating common typography.

    Catches rule-authored typography (em-dashes, smart quotes, ellipses)
    that would otherwise land in a saved text report as the mojibake
    Windows PowerShell produces when it re-decodes UTF-8 through cp1252.

    Known glyphs are mapped to readable equivalents (em-dash -> '-',
    ellipsis -> '...', etc.).  Anything else non-ASCII is replaced with
    ``'?'`` so the returned string is guaranteed pure ASCII.

    Applied at the output boundary of the text reporters, so rule data is
    flattened exactly once, at the moment we hand it to stdout / a file.
    """
    if not s:
        return s
    out: list[str] = []
    for ch in s:
        code = ord(ch)
        if code < 128:
            out.append(ch)
        else:
            out.append(_ASCII_MAP.get(ch, "?"))
    return "".join(out)
