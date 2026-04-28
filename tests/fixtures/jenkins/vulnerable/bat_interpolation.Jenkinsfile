// Triggers: SEC6-JK-007 — Windows bat step with Groovy string interpolation of params
pipeline {
    agent { label 'windows' }
    parameters {
        string(name: 'PROJECT_FILE', defaultValue: 'solution.sln', description: 'Solution file')
    }
    stages {
        stage('Build') {
            steps {
                bat "msbuild ${params.PROJECT_FILE} /t:Build /p:Configuration=Release"
            }
        }
    }
}
