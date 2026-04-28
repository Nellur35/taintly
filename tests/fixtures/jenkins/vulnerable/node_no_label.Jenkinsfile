// Triggers: SEC7-JK-002 — scripted pipeline node block without agent label
node {
    stage('Checkout') {
        checkout scm
    }
    stage('Build') {
        sh 'make build'
    }
    stage('Test') {
        sh 'make test'
    }
}
