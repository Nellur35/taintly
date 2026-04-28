#!/usr/bin/env groovy
/*
 * Realistic web application build + deploy pipeline.
 * Common pattern in enterprise Jenkins setups.
 *
 * EXPECTED FINDINGS:
 *   SEC5-JK-001  — deploy stage present but no disableConcurrentBuilds
 *   SEC4-JK-004  — input step without submitter restriction
 *   SEC6-JK-005  — long-lived AWS credentials in environment block
 *   SEC9-JK-002  — archiveArtifacts without fingerprint
 */

pipeline {
    agent { label 'docker-builder' }

    environment {
        APP_NAME    = 'my-web-app'
        REGISTRY    = 'registry.example.com'
        IMAGE_TAG   = "${env.GIT_COMMIT[0..7]}"
        // Long-lived cloud credentials in environment block
        AWS_ACCESS_KEY_ID     = credentials('aws-access-key')
        AWS_SECRET_ACCESS_KEY = credentials('aws-secret-key')
        AWS_DEFAULT_REGION    = 'us-east-1'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build') {
            steps {
                timeout(time: 20, unit: 'MINUTES') {
                    sh '''
                        docker build \
                            --build-arg BUILD_DATE="$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
                            --build-arg VCS_REF="${GIT_COMMIT}" \
                            -t ${REGISTRY}/${APP_NAME}:${IMAGE_TAG} \
                            -t ${REGISTRY}/${APP_NAME}:latest \
                            .
                    '''
                }
            }
        }

        stage('Test') {
            steps {
                timeout(time: 30, unit: 'MINUTES') {
                    sh '''
                        docker run --rm \
                            -v "${WORKSPACE}/reports:/app/reports" \
                            ${REGISTRY}/${APP_NAME}:${IMAGE_TAG} \
                            npm test -- --reporter junit --reporter-options mochaFile=reports/junit.xml
                    '''
                }
            }
            post {
                always {
                    junit testResults: 'reports/junit.xml', allowEmptyResults: true
                    archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
                }
            }
        }

        stage('Push Image') {
            when { branch 'main' }
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'registry-creds',
                    usernameVariable: 'REGISTRY_USER',
                    passwordVariable: 'REGISTRY_PASS',
                )]) {
                    sh '''
                        echo "$REGISTRY_PASS" | docker login ${REGISTRY} -u "$REGISTRY_USER" --password-stdin
                        docker push ${REGISTRY}/${APP_NAME}:${IMAGE_TAG}
                        docker push ${REGISTRY}/${APP_NAME}:latest
                    '''
                }
            }
        }

        stage('Deploy to Staging') {
            when { branch 'main' }
            steps {
                timeout(time: 15, unit: 'MINUTES') {
                    sh '''
                        aws ecs update-service \
                            --cluster staging \
                            --service ${APP_NAME} \
                            --force-new-deployment \
                            --region ${AWS_DEFAULT_REGION}
                        aws ecs wait services-stable \
                            --cluster staging \
                            --services ${APP_NAME}
                    '''
                }
            }
        }

        stage('Deploy to Production') {
            when { branch 'main' }
            steps {
                // No submitter restriction — any Jenkins user can approve
                input message: 'Deploy to production?', ok: 'Deploy'

                timeout(time: 15, unit: 'MINUTES') {
                    sh '''
                        aws ecs update-service \
                            --cluster production \
                            --service ${APP_NAME} \
                            --force-new-deployment \
                            --region ${AWS_DEFAULT_REGION}
                        aws ecs wait services-stable \
                            --cluster production \
                            --services ${APP_NAME}
                    '''
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo "Pipeline completed successfully for ${APP_NAME}:${IMAGE_TAG}"
        }
        failure {
            echo "Pipeline failed for ${APP_NAME}:${IMAGE_TAG}"
        }
    }
}
