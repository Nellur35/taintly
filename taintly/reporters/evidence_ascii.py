"""Small deterministic text view of rule-produced, ordered evidence."""

from __future__ import annotations

from pathlib import Path

from taintly.models import EvidenceTrace

from ._encoding import strip_terminal_controls, to_ascii

_WIDTH = 72
_INDENT = "    "


def _label(value: str, limit: int) -> str:
    clean = to_ascii(strip_terminal_controls(value))
    clean = " ".join(clean.replace("[", "(").replace("]", ")").replace("|", "/").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - len("... [truncated]")] + "... [truncated]"


def _line(value: str) -> str:
    if len(value) > _WIDTH - len(_INDENT):
        marker = "... [truncated]"
        value = value[: _WIDTH - len(_INDENT) - len(marker)] + marker
    return _INDENT + value


def format_evidence_trace(trace: EvidenceTrace, finding_file: str) -> list[str]:
    """Render supplied evidence only; never derive edges from source or prose."""
    if not 2 <= len(trace.steps) <= 4:
        return [_line(f"Evidence path omitted: {len(trace.steps)} steps exceed display profile")]
    if any(step.file != finding_file or step.line <= 0 for step in trace.steps):
        return [_line("Evidence path unavailable: source reference mismatch")]

    out = [
        _line(f"Evidence path ({_label(trace.basis, 45)}):"),
        _line(f"Context: {_label(trace.context, 58)}"),
    ]
    for index, step in enumerate(trace.steps):
        out.append(_line(f"  [{_label(step.label, 48)}] E{index + 1}"))
        if index < len(trace.steps) - 1:
            out.extend(
                [
                    _line("           |"),
                    _line(f"           | {_label(step.relation_to_next, 48)}"),
                    _line("           v"),
                ]
            )
    if trace.unknowns:
        out.append(_line("Unknown:"))
        for unknown in trace.unknowns[:5]:
            out.append(_line(f"  - {_label(unknown, 58)}"))
        if len(trace.unknowns) > 5:
            out.append(_line(f"  ... {len(trace.unknowns) - 5} more unknowns omitted"))
    out.append(_line(f"Runtime: {_label(trace.runtime_status, 57)}"))
    out.append(_line("References (relative to File above):"))
    for index, step in enumerate(trace.steps):
        name = _label(Path(step.file).name, 43)
        out.append(_line(f"  E{index + 1}: {name}:{step.line}"))
    return out
