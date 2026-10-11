"""Secret interpolation mutants must retain an executable script field."""
from taintly.parsers.structural import EventKind, walk_workflow
from taintly.testing.mutations import mutate_whitespace_pad


def test_valid_spacing_remains_detected_and_colon_collapse_loses_run_mapping(all_rules):
    rule = next(rule for rule in all_rules if rule.id == "SEC6-GH-005")
    content = (
        "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - run: echo ${{ secrets.TOKEN }} X= 1\n"
    )
    variants = mutate_whitespace_pad(content)
    assert len(variants) == 3
    assert rule.pattern.check(content, content.splitlines())
    assert rule.pattern.check(variants[0], variants[0].splitlines())
    assert rule.pattern.check(variants[2], variants[2].splitlines())
    collapsed = variants[1]
    leaves = [e for e in walk_workflow("workflow.yml", content=collapsed)
              if e.kind is EventKind.LEAF_SCALAR]
    assert not any(len(e.path) == 5 and e.path[-1] == "run" for e in leaves)
    assert rule.pattern.check(collapsed, collapsed.splitlines()) == []
