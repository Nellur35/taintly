// Triggers: SEC9-JK-003 — wget downloads binary without checksum verification
pipeline {
    agent { label 'linux' }
    stages {
        stage('Setup') {
            steps {
                sh 'wget -q https://releases.example.com/tool-v2.0.tar.gz'
                sh 'tar xzf tool-v2.0.tar.gz'
                sh './tool-v2.0/install.sh'
            }
        }
    }
}
