// Triggers: SEC8-JK-002 — remote Groovy script fetched and executed via URL
pipeline {
    agent { label 'linux' }
    stages {
        stage('Bootstrap') {
            steps {
                script {
                    def bootstrapScript = new URL('https://raw.githubusercontent.com/org/scripts/main/bootstrap.groovy').text
                    evaluate(bootstrapScript)
                }
            }
        }
    }
}
