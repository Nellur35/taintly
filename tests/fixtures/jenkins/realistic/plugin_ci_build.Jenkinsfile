#!/usr/bin/env groovy
/*
 * Realistic plugin CI build pipeline.
 * Modelled on jenkinsci/blueocean-plugin scripted pipeline pattern.
 *
 * EXPECTED FINDINGS:
 *   SEC7-JK-002  — node() without agent label
 *   SEC9-JK-002  — archiveArtifacts without fingerprint
 */

def credentials = [
    file(credentialsId: 'deploy-live-properties', variable: 'LIVE_PROPERTIES_FILE'),
    file(credentialsId: 'ath-ssh-key', variable: 'ATH_KEY_FILE'),
]

def buildEnvs = [
    'GIT_COMMITTER_EMAIL=ci@example.org',
    'GIT_COMMITTER_NAME=CI Bot',
    'GIT_AUTHOR_NAME=CI Bot',
    'GIT_AUTHOR_EMAIL=ci@example.org',
]

def jenkinsVersions = ['2.440.3', '2.452.1']

node() {
    withCredentials(credentials) {
        withEnv(buildEnvs) {

            stage('Checkout') {
                deleteDir()
                checkout scm
                sh 'mv $LIVE_PROPERTIES_FILE acceptance-tests/live.properties'
                configFileProvider([configFile(fileId: 'maven-settings-nexus', variable: 'MAVEN_SETTINGS')]) {
                    sh 'cp $MAVEN_SETTINGS settings.xml'
                }
                sh 'mv $ATH_KEY_FILE acceptance-tests/ath.key'
            }

            try {
                docker.image('myorg/build-tools:21.0.3-jdk').inside('--net=host --memory=4g') {
                    def ip = sh(returnStdout: true, script: "hostname -I | awk '{print \$1}'").trim()

                    stage('Build & Unit Test') {
                        timeout(time: 90, unit: 'MINUTES') {
                            try {
                                sh """
                                    mvn clean install -T2 -Pci -V -B \\
                                        -DforkCount=3 \\
                                        -Dmaven.test.failure.ignore \\
                                        -s settings.xml \\
                                        -Dmaven.repo.local=/tmp/m2 \\
                                        -Dmaven.artifact.threads=30
                                """
                            } finally {
                                junit testResults: '**/target/surefire-reports/TEST-*.xml', allowEmptyResults: true
                                junit testResults: '**/target/jest-reports/*.xml',          allowEmptyResults: true
                                archiveArtifacts artifacts: '*/target/*.hpi', allowEmptyArchive: true
                            }
                        }
                    }

                    jenkinsVersions.each { version ->
                        stage("ATH — Jenkins ${version}") {
                            timeout(time: 90, unit: 'MINUTES') {
                                dir('acceptance-tests') {
                                    sh """
                                        bash -x ./run.sh \\
                                            -v=${version} \\
                                            --host=${ip} \\
                                            --no-selenium \\
                                            -ci \\
                                            --settings='-s ${env.WORKSPACE}/settings.xml' \\
                                            --maven-local-repo=/tmp/m2
                                    """
                                    junit '**/target/surefire-reports/*.xml'
                                }
                            }
                        }
                    }
                }
            } finally {
                stage('Cleanup') {
                    catchError(message: 'Suppressing cleanup error') {
                        deleteDir()
                    }
                }
            }
        }
    }
}
