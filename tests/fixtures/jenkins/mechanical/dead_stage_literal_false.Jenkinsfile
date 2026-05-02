pipeline {
  agent { label 'trusted-linux' }
  stages {
    stage('Dead') {
      when {
        expression { false }
      }
      steps {
        sh "echo ${params.BRANCH_NAME}"
      }
    }
  }
}
