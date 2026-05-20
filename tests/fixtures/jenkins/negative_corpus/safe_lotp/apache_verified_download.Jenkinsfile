// Sanitized from apache/cassandra agent-maintenance shell shape.
pipeline {
  agent { label 'linux && docker' }
  stages {
    stage('agent maintenance') {
      steps {
        sh '''#!/bin/bash
          set -euo pipefail
          agent_scripts_url="https://raw.githubusercontent.com/example/builds/main/agent_scripts"
          wget -q "${agent_scripts_url}/docker_agent_cleaner.sh"
          wget -q "${agent_scripts_url}/docker_agent_cleaner.sh.sha256"
          sha256sum -c docker_agent_cleaner.sh.sha256
          bash docker_agent_cleaner.sh 24
        '''
      }
    }
  }
}
