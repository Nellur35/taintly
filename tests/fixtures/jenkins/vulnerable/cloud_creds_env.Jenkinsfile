// Triggers: SEC6-JK-005 — long-lived cloud credential in environment block
pipeline {
    agent { label 'linux' }
    environment {
        AWS_ACCESS_KEY_ID     = 'AKIAIOSFODNN7EXAMPLE'
        AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        AWS_DEFAULT_REGION    = 'us-east-1'
    }
    stages {
        stage('Deploy') {
            steps {
                sh 'aws s3 sync dist/ s3://my-bucket/'
            }
        }
    }
}
