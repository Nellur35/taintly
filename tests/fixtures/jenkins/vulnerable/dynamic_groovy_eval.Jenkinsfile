// Triggers: SEC4-JK-003 — dynamic Groovy evaluation via evaluate()
pipeline {
    agent { label 'linux' }
    parameters {
        string(name: 'TARGET', defaultValue: 'staging', description: 'Deploy target')
    }
    stages {
        stage('Deploy') {
            steps {
                evaluate("deploy${params.TARGET}()")
            }
        }
    }
}
