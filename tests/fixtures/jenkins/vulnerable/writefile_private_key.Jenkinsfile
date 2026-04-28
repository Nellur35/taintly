// Triggers: SEC6-JK-006 — writeFile writes private key material to workspace
pipeline {
    agent { label 'linux' }
    stages {
        stage('Deploy') {
            steps {
                writeFile file: 'deploy.pem', text: env.SSH_PRIVATE_KEY
                sh 'ssh -i deploy.pem deployer@prod.example.com ./deploy.sh'
                sh 'rm -f deploy.pem'
            }
        }
    }
}
