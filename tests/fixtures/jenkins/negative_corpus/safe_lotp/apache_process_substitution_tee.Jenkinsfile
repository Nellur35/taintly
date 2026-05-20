// Sanitized from apache/cassandra test log compression.
// The shell uses process substitution with tee/xz, but not downloaded code.
pipeline {
  agent { label 'linux && docker' }
  stages {
    stage('test') {
      steps {
        sh label: 'RUNNING TESTS', script: '''#!/bin/bash
          set -o pipefail
          .build/docker/run-tests.sh -a unit -j 17 2>&1 | tee >(xz -c > build/test.log.xz)
        '''
      }
    }
  }
}
