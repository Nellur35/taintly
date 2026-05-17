// SEC9-JK-004 negative fixture — safe download patterns and unrelated
// string literals that contain the substring "curl | bash".
//
// Must produce ZERO findings for SEC9-JK-004:
//   * Safe download: fetch → sha256sum --check → bash <file>.
//   * curl | jq: jq is not an interpreter; not a download-execute.
//   * environment block string literal mentioning "curl|bash" in
//     prose — walker emits value_kind='string' (not 'shell') so the
//     rule's structural-reader predicate never sees it.
//   * Commented-out shell sinks — walker does not emit LEAFs for
//     Groovy comments.
pipeline {
    agent any

    environment {
        // String literal mentioning curl | bash in DOC prose — must NOT
        // fire because the walker yields value_kind='string' here,
        // not 'shell'.  This is the FP class SEC9-JK-001's line-regex
        // would have caught but the structural reader rules out.
        DOC_NOTE = 'Avoid running curl https://x | bash in CI'
    }

    stages {
        stage('Safe download') {
            steps {
                sh '''
                    curl -fsSL https://releases.example.com/installer.sh -o installer.sh
                    echo 'a1b2c3d4e5f6  installer.sh' | sha256sum --check
                    bash installer.sh
                    rm installer.sh
                '''
            }
        }
        stage('JSON ingestion') {
            steps {
                // jq is not an interpreter — must NOT fire.
                sh 'curl -s https://api.example.com/v1/health | jq .ok'
            }
        }
        stage('Commented-out danger') {
            steps {
                // sh 'curl https://x.example.com/x.sh | bash'   <-- walker skips comments
                sh 'make build'
            }
        }
    }
}
