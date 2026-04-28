// Triggers: SEC9-JK-001 — curl piped directly to bash without integrity check
pipeline {
    agent { label 'linux' }
    stages {
        stage('Setup') {
            steps {
                sh 'curl -fsSL https://get.helm.sh/install.sh | bash'
            }
        }
    }
}
