"""Authored scope guards for the saved FileVault PR profile."""

import pytest

from taintly.ingestion.jenkins_filevault import _recipe
from taintly.ingestion.jenkins_incrementals import IncrementalsEvidenceError

RECIPE = b"""\
@Library('filevault@master') _
vaultPipeline('ubuntu', 11, '3', {
  vaultStageSanityCheck()
  vaultStageBuild(['Windows'], [17], ['3.6.3'], 'apache_jackrabbit-filevault-package-maven-plugin', [
    hasSeparateItExecution: true
  ])
  vaultStageIT(['Windows', 'ubuntu'], [8, 17, 21], ['3'])
  vaultStageDeploy()
})
"""


def test_owned_publisher_call_survives_supported_integration_matrix_change():
    assert _recipe(RECIPE) == 8
    assert _recipe(RECIPE.replace(b"[8, 17, 21], ['3']", b"[11, 17], ['3', '4']")) == 8


@pytest.mark.parametrize(
    "change",
    [
        b"println 'vaultStageDeploy()'",
        b"if (false) { vaultStageDeploy() }",
        b"vaultStageDeploy(); sh('mvn deploy')",
    ],
)
def test_other_or_disabled_source_cannot_establish_exclusion(change):
    with pytest.raises(IncrementalsEvidenceError, match="outside the reviewed FileVault recipe"):
        _recipe(RECIPE.replace(b"vaultStageDeploy()", change))
