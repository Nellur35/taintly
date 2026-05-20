// Sanitized from jenkinsci/docker tag-gated publish shape.
// The publish command is release-tag gated and has no PR-context source.
node('linux') {
  stage('Publish') {
    if (env.TAG_NAME && env.PUBLISH == 'true') {
      sh 'make docker-init'
      sh 'make publish'
    }
  }
}
