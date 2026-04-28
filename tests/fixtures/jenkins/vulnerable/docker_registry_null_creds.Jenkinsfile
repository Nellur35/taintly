// Triggers: SEC7-JK-003 — docker.withRegistry with null credentials
pipeline {
    agent { label 'linux' }
    stages {
        stage('Push') {
            steps {
                docker.withRegistry('https://registry.example.com', null) {
                    docker.build('myapp:latest').push()
                }
            }
        }
    }
}
