#!/usr/bin/env groovy
/*
 * Realistic release pipeline.
 * Modelled closely on eclipse-jkube/jkube release process.
 *
 * EXPECTED FINDINGS:
 *   SEC7-JK-001  — agent any (unconstrained agent)
 *   SEC1-JK-002  — no global timeout
 *   SEC5-JK-001  — release stage present but no disableConcurrentBuilds
 *   SEC10-JK-001 — no post { always { } } block
 */

pipeline {
  agent any
  tools {
    maven 'apache-maven-3.9'
    jdk   'temurin-jdk17-latest'
  }
  stages {
    stage('Prepare Release') {
      steps {
        withCredentials([
          file(credentialsId: 'gpg-secret-subkeys', variable: 'KEYRING'),
          string(credentialsId: 'github-token', variable: 'GH_TOKEN'),
        ]) {
          sh '''
            gpg --batch --import "${KEYRING}"
            for fpr in $(gpg --list-keys --with-colons | awk -F: '/fpr:/ {print $10}' | sort -u); do
                echo -e "5\ny\n" | gpg --batch --command-fd 0 --expert --edit-key ${fpr} trust
            done
          '''

          sh '''
            git config --global user.email "release-bot@example.org"
            git config --global user.name  "Release Bot"

            git clone https://release-bot:$GH_TOKEN@github.com/example-org/my-library.git && cd my-library

            PROJECT_VERSION=$(mvn -q -Dexec.executable=echo \
                -Dexec.args='${project.version}' --non-recursive exec:exec)
            NEXT_RELEASE_VERSION=`echo $PROJECT_VERSION | sed 's/-SNAPSHOT//g'`
            if [ ${#NEXT_RELEASE_VERSION} -eq 3 ]; then
                NEXT_RELEASE_VERSION=`echo "$NEXT_RELEASE_VERSION.0"`
            fi

            echo "Releasing $NEXT_RELEASE_VERSION"

            mvn versions:set -DnewVersion=$NEXT_RELEASE_VERSION
            find . -iname '*.versionsBackup' -exec rm {} +
            git add . && git commit -m "[RELEASE] version $NEXT_RELEASE_VERSION"
            git tag $NEXT_RELEASE_VERSION
            git push origin $NEXT_RELEASE_VERSION
            git push origin main

            mvn clean -B
            mvn -V -B -e -U install \
                org.sonatype.plugins:nexus-staging-maven-plugin:1.6.7:deploy \
                -P release \
                -DnexusUrl=https://oss.sonatype.org \
                -DserverId=ossrh

            MAJOR_VERSION=`echo $NEXT_RELEASE_VERSION | cut -d. -f1`
            MINOR_VERSION=`echo $NEXT_RELEASE_VERSION | cut -d. -f2`
            PATCH_VERSION=`echo $NEXT_RELEASE_VERSION | cut -d. -f3`
            PATCH_VERSION=$(($PATCH_VERSION + 1))
            NEXT_SNAPSHOT_VERSION=`echo "$MAJOR_VERSION.$MINOR_VERSION.$PATCH_VERSION-SNAPSHOT"`

            mvn versions:set -DnewVersion=$NEXT_SNAPSHOT_VERSION
            find . -iname '*.versionsBackup' -exec rm {} +
            git add . && git commit -m "[RELEASE] next dev iteration $NEXT_SNAPSHOT_VERSION"
            git push origin main

            repo_id=$(cat target/nexus-staging/staging/*.properties | grep id | awk -F'=' '{print $2}')
            mvn -B org.sonatype.plugins:nexus-staging-maven-plugin:1.6.5:rc-release \
                -DserverId=ossrh \
                -DnexusUrl=https://oss.sonatype.org \
                -DstagingRepositoryId=${repo_id} \
                -Ddescription="Next release is ready" \
                -DstagingProgressTimeoutMinutes=60
          '''
        }
      }
    }
  }
}
