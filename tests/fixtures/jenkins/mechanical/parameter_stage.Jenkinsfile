pipeline {
  agent { label 'trusted-linux' }
  parameters {
    string(name: 'BRANCH_NAME', defaultValue: 'main')
  }
  stages {
    stage('Parameter driven') {
      steps {
        sh "echo ${params.BRANCH_NAME}"
      }
    }
  }
}
