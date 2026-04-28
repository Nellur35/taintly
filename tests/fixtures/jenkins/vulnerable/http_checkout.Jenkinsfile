// Triggers: SEC8-JK-003 — git checkout from non-HTTPS (plain HTTP) URL
pipeline {
    agent { label 'linux' }
    stages {
        stage('Checkout') {
            steps {
                checkout([$class: 'GitSCM',
                    userRemoteConfigs: [[
                        url: 'http://github.com/org/repo.git'
                    ]]
                ])
            }
        }
    }
}
