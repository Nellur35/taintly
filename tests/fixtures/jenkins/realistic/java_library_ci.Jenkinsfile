#!/usr/bin/env groovy
/*
 * Realistic CI pipeline for a Java library.
 *
 * EXPECTED: CLEAN — 0 findings (or only low-severity)
 */

@Library('jenkins-infra@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2') _

properties([
    disableConcurrentBuilds(abortPrevious: true),
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5')),
])

def splits
def isReleaseBranch = env.BRANCH_NAME ==~ /^(main|release\/.+)$/

stage('Determine test splits') {
    node('maven-21') {
        checkout scm
        splits = splitTests parallelism: count(4), generateInclusions: true, estimateTestsFromFiles: true
    }
}

def branches = [failFast: true]

for (int i = 0; i < splits.size(); i++) {
    def num = i
    def split = splits[num]

    branches["shard-${num}"] = {
        node('maven-21') {
            timeout(time: 90, unit: 'MINUTES') {
                checkout scm
                try {
                    def includesFile = "${env.WORKSPACE_TMP}/includes-${num}.txt"
                    def excludesFile = "${env.WORKSPACE_TMP}/excludes-${num}.txt"
                    writeFile file: (split.includes ? includesFile : excludesFile), text: split.list.join('\n')
                    writeFile file: (split.includes ? excludesFile : includesFile), text: ''

                    sh """
                        mvn -B -ntp -V \
                            -Dsurefire.includesFile="${includesFile}" \
                            -Dsurefire.excludesFile="${excludesFile}" \
                            clean verify
                    """
                } finally {
                    junit testResults: 'target/surefire-reports/*.xml', allowEmptyResults: true
                }
            }
        }
    }
}

parallel branches

stage('Publish') {
    node('maven-21') {
        timeout(time: 30, unit: 'MINUTES') {
            checkout scm

            if (isReleaseBranch) {
                withCredentials([
                    usernamePassword(
                        credentialsId: 'nexus-deploy',
                        usernameVariable: 'NEXUS_USER',
                        passwordVariable: 'NEXUS_PASS',
                    )
                ]) {
                    sh '''
                        mvn -B -ntp -V \
                            -DaltDeploymentRepository=nexus::default::https://nexus.example.com/repository/releases/ \
                            deploy
                    '''
                }
            }

            archiveArtifacts(
                artifacts: 'target/*.jar,target/*.pom',
                allowEmptyArchive: true,
                fingerprint: true,
            )
        }
    }
}
