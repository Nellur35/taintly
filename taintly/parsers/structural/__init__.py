"""Schema-bounded structural CI YAML reader.

Public entry point: :func:`walk_workflow`.

NOT a full YAML parser.  Scope-limited to the structural shapes
that GitHub Actions and GitLab CI workflow files actually produce.
Jenkinsfile is out of scope (Groovy DSL, not YAML).

See ``docs/STRUCTURAL_READER_SCOPE.md`` for the supported feature
list, the cutoff-recovery contract, anchor merge-key behaviour,
and the schema-lookup performance choice.
"""

from .api import walk_workflow
from .walker import Event, EventKind

__all__ = ["walk_workflow", "Event", "EventKind"]
