// Jenkinsfile fixture — expected findings: AI-JK-004 (joblib.load)
@Library('shared-lib@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2') _

pipeline {
    agent { label 'ml-linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Score') {
            steps {
                sh 'python -c "import joblib; m = joblib.load(\'models/churn.pkl\')"'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
