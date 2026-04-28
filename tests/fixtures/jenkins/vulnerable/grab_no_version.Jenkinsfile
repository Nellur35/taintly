// Triggers: SEC3-JK-002 — @Grab without explicit version (resolves to latest at runtime)
@Grab('org.apache.commons:commons-lang3')
import org.apache.commons.lang3.StringUtils

pipeline {
    agent { label 'linux' }
    stages {
        stage('Build') {
            steps {
                script {
                    echo StringUtils.capitalize('hello world')
                }
            }
        }
    }
}
