// Triggers: SEC2-JK-001 — credential stored as password build parameter
pipeline {
    agent { label 'linux' }
    parameters {
        password(name: 'DEPLOY_SECRET', defaultValue: '', description: 'Deployment API secret')
        string(name: 'ENV', defaultValue: 'staging', description: 'Target environment')
    }
    stages {
        stage('Deploy') {
            steps {
                sh 'curl -H "Authorization: Bearer $DEPLOY_SECRET" https://api.example.com/deploy'
            }
        }
    }
}
