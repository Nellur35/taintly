// Triggers: SEC6-JK-004 — TLS certificate verification disabled (curl -k)
pipeline {
    agent { label 'linux' }
    stages {
        stage('Fetch Config') {
            steps {
                sh 'curl -k https://internal.example.com/config.json -o config.json'
            }
        }
    }
}
