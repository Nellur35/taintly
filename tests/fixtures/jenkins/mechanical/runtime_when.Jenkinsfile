pipeline {
  agent { label 'trusted-linux' }
  stages {
    stage('Maybe') {
      when {
        expression { params.RUN_DEPLOY == 'true' }
      }
      steps {
        sh "echo ${params.BRANCH_NAME}"
      }
    }
  }
}
