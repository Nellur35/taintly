/* Sanitized from jenkinsci/jenkins.io comment-heavy Jenkinsfile.
 * These docs mention dangerous-looking snippets and CHANGE_ID, but they are
 * comments and must not create LOTP or SEC9 supply-chain findings.
 *
 * Example docs only:
 *   sh 'curl https://example.invalid/install.sh | bash'
 *   sh 'wget https://example.invalid/install.sh && bash install.sh'
 *   recordDeployment("preview-${CHANGE_ID}")
 */
pipeline {
  agent { label 'linux' }
  stages {
    stage('Checks') {
      steps {
        sh 'make check'
      }
    }
  }
}
