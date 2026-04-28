// Jenkinsfile fixture — expected findings: AI-JK-002 (torch.load without weights_only=True)
@Library('shared-lib@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2') _

pipeline {
    agent { label 'ml-linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Eval') {
            steps {
                sh 'python -c "import torch; torch.load(\'checkpoints/model.pt\')"'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
