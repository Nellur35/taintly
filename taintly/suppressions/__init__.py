"""Inline-suppression interop with foreign scanners.

Each module in this package recognises one external scanner's
inline-suppression comment format and maps its rule IDs onto the
nearest equivalent taintly rule IDs.  Honour-or-not is gated by an
explicit CLI flag — taintly never silently changes its behaviour
based on another tool's suppressions without the user opting in.
"""
