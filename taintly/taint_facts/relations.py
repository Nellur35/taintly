"""Relation store for the taint facts model.

A :class:`Database` holds *facts* grouped into named *relations*.
Within one relation a fact is identified by its **key columns** only
(:meth:`Fact.fact_key`); the rest of the tuple — for taint facts, the
provenance ``hops`` chain and the source line — is payload.

On a key collision the fact with the lower :meth:`Fact.fact_rank`
wins.  For the derived taint relations the rank is the length of the
hop chain (then a deterministic tie-break), so the stored provenance
is the *shortest* proof and is independent of the order rules fire.
That keeps the fixed point a genuine monotone set-closure — keys are
only ever added — while still letting each fact carry the hop chain
the rule layer needs to render :class:`~taintly.taint.TaintPath`.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterator
from typing import Protocol, runtime_checkable


@runtime_checkable
class Fact(Protocol):
    """A row in a relation.

    Implementations are expected to be small frozen dataclasses.
    ``fact_key`` must cover exactly the columns that identify the row;
    ``fact_rank`` orders competing derivations of the *same* key so
    the store can keep the best one.
    """

    def fact_key(self) -> Hashable:
        """The identifying columns of this fact (not the payload)."""
        ...

    def fact_rank(self) -> tuple:
        """Ordering key for competing derivations; lower wins."""
        ...


class Database:
    """A set of named relations, each deduped on ``Fact.fact_key``.

    The store is deliberately tiny: CI files are small and bounded, so
    the relations stay in plain dicts and the closure evaluator scans
    them directly.  Indexing, if it is ever needed, belongs in the
    rule functions, not here.
    """

    __slots__ = ("_relations",)

    def __init__(self) -> None:
        self._relations: dict[str, dict[Hashable, Fact]] = {}

    def add(self, relation: str, fact: Fact) -> bool:
        """Insert ``fact`` into ``relation``.

        Returns ``True`` when the store changed — either the key was
        new, or ``fact`` is a strictly better (lower-ranked)
        derivation of an existing key.  The closure loop uses that
        signal to decide whether another pass is needed.
        """
        table = self._relations.setdefault(relation, {})
        key = fact.fact_key()
        existing = table.get(key)
        if existing is None:
            table[key] = fact
            return True
        if fact.fact_rank() < existing.fact_rank():
            table[key] = fact
            return True
        return False

    def all(self, relation: str) -> list[Fact]:
        """Every fact currently in ``relation`` (insertion order)."""
        return list(self._relations.get(relation, {}).values())

    def get(self, relation: str, key: Hashable) -> Fact | None:
        """The fact stored for ``key`` in ``relation``, or ``None``."""
        table = self._relations.get(relation)
        return table.get(key) if table is not None else None

    def has(self, relation: str, key: Hashable) -> bool:
        return key in self._relations.get(relation, {})

    def __iter__(self) -> Iterator[str]:
        return iter(self._relations)
