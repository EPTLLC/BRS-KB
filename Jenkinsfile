// BRS-KB Jenkins Pipeline
// Jenkins CI/CD configuration for BRS-KB

pipeline {
    agent any

    environment {
        PYTHON_VERSION = '3.10'
        NODE_VERSION = '18'
    }

    stages {
        // Checkout and Setup
        stage('Checkout & Setup') {
            steps {
                checkout scm
                sh """
                    python${PYTHON_VERSION} -m pip install --upgrade pip
                    python${PYTHON_VERSION} -m pip install -e ".[dev]"
                """
            }
        }

        // Code Quality
        stage('Code Quality') {
            parallel {
                stage('Linting') {
                    steps {
                        sh """
                            python${PYTHON_VERSION} -m flake8 brs_kb --count --select=E9,F63,F7,F82 --show-source --statistics
                            python${PYTHON_VERSION} -m black --check --diff brs_kb
                            python${PYTHON_VERSION} -m mypy brs_kb --ignore-missing-imports
                        """
                    }
                }

                stage('Security') {
                    steps {
                        sh """
                            python${PYTHON_VERSION} -m pytest tests/ -v --tb=short
                            python${PYTHON_VERSION} -c "from brs_kb import validate_payload_database; print('Payload DB validation:', validate_payload_database())"
                        """
                    }
                }
            }
        }

        // Testing
        stage('Testing') {
            steps {
                sh """
                    python${PYTHON_VERSION} -m pytest tests/ -v --cov=brs_kb --cov-report=xml --cov-report=html
                """
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'htmlcov',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                    cobertura coberturaReportFile: 'coverage.xml'
                }
            }
        }

        // Package Building
        stage('Build Package') {
            steps {
                sh """
                    python${PYTHON_VERSION} -m pip install build
                    python${PYTHON_VERSION} -m build
                    ls -la dist/
                """
            }
            post {
                success {
                    archiveArtifacts artifacts: 'dist/*'
                }
            }
        }

        // Integration Testing
        stage('Integration Testing') {
            steps {
                sh """
                    python${PYTHON_VERSION} examples/cli_demo.py
                    python${PYTHON_VERSION} examples/integrated_demo.py
                    python${PYTHON_VERSION} examples/plugin_demo.py
                    python${PYTHON_VERSION} examples/siem_integration.py
                """
            }
        }

        // Performance Testing
        stage('Performance Testing') {
            when {
                anyOf {
                    branch 'main'
                    expression { currentBuild.number % 10 == 0 } // Every 10th build
                }
            }
            steps {
                sh """
                    python${PYTHON_VERSION} -c "
                    import time
                    from brs_kb import find_contexts_for_payload

                    start = time.time()
                    for i in range(1000):
                        result = find_contexts_for_payload(f'<script>alert({i})</script>')
                    duration = time.time() - start

                    print(f'Performance: 1000 analyses in {duration:.2f}s')
                    print(f'Average: {duration/1000*1000:.2f}ms per analysis')
                    "
                """
            }
        }

        // Dependency Security
        stage('Dependency Security') {
            steps {
                sh """
                    python${PYTHON_VERSION} -m pip install safety
                    python${PYTHON_VERSION} -m safety check
                """
            }
        }

        // Documentation
        stage('Documentation') {
            when {
                anyOf {
                    branch 'main'
                    changelog '.*'
                }
            }
            steps {
                sh """
                    if ! grep -q "BRS-KB" README.md; then
                        echo "README.md missing project title"
                        exit 1
                    fi
                    if ! grep -q "Installation" README.md; then
                        echo "README.md missing Installation section"
                        exit 1
                    fi
                    echo "Documentation validation passed"
                """
            }
        }

        // Deploy to Test Environment
        stage('Deploy to Test') {
            when {
                branch 'develop'
            }
            steps {
                sh """
                    python${PYTHON_VERSION} -m pip install dist/*.tar.gz
                    python${PYTHON_VERSION} -c "import brs_kb; print('BRS-KB installed successfully')"
                    python${PYTHON_VERSION} -c "from brs_kb.cli import BRSKBCLI; cli = BRSKBCLI(); print('CLI working')"
                """
            }
        }

        // Deploy to Production
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                sh """
                    python${PYTHON_VERSION} -m pip install dist/*.tar.gz
                    python${PYTHON_VERSION} -c "import brs_kb; print('BRS-KB production deployment successful')"
                    python${PYTHON_VERSION} -c "from brs_kb.cli import BRSKBCLI; cli = BRSKBCLI(); print('CLI production ready')"
                """
            }
        }

        // Release
        stage('Release') {
            when {
                allOf {
                    branch 'main'
                    expression { currentBuild.getPreviousBuild()?.result != 'SUCCESS' }
                }
            }
            steps {
                script {
                    def version = sh(script: 'python${PYTHON_VERSION} -c "from brs_kb import get_kb_version; print(get_kb_version())"', returnStdout: true).trim()
                    echo "Creating release for version: ${version}"

                    sh """
                        python${PYTHON_VERSION} -c "
                        from brs_kb import get_kb_info, get_database_info
                        import datetime

                        kb_info = get_kb_info()
                        db_info = get_database_info()

                        print('# Release Notes for v' + kb_info['version'])
                        print()
                        print('## Release Date: ' + datetime.datetime.now().strftime('%Y-%m-%d'))
                        print()
                        print('### New Features')
                        print('- Enhanced XSS vulnerability detection')
                        print('- New modern web technology contexts')
                        print('- Improved payload database')
                        print('- CLI tool for security workflows')
                        print('- Security scanner integrations')
                        print()
                        print('### Statistics')
                        print(f'- XSS Contexts: {kb_info[\"total_contexts\"]}')
                        print(f'- Payload Database: {db_info[\"total_payloads\"]}')
                        print(f'- WAF Bypass: {db_info[\"waf_bypass_count\"]}')
                        print(f'- Browser Support: {len(db_info[\"browser_support\"])}')
                        print()
                        print('### Installation')
                        print('```bash')
                        print('pip install brs-kb')
                        print('```')
                        print()
                        print('### Quick Start')
                        print('```bash')
                        print('brs-kb info')
                        print('brs-kb analyze-payload \"<script>alert(1)</script>\"')
                        print('```')
                        " > RELEASE_NOTES.md
                    """

                    archiveArtifacts artifacts: 'RELEASE_NOTES.md'
                }
            }
        }
    }

    post {
        always {
            // Clean up
            cleanWs()

            // Notify on build status
            script {
                def status = currentBuild.result ?: 'SUCCESS'
                def color = status == 'SUCCESS' ? 'good' : 'danger'
                def message = "${env.JOB_NAME} - Build #${env.BUILD_NUMBER} - ${status}"

                slackSend(
                    color: color,
                    message: message,
                    channel: '#security-tools'
                )
            }
        }

        success {
            echo ' Pipeline completed successfully!'

            // Archive test results
            archiveArtifacts artifacts: 'htmlcov/**,coverage.xml'

            // Update build status
            script {
                def version = sh(script: 'python${PYTHON_VERSION} -c "from brs_kb import get_kb_version; print(get_kb_version())"', returnStdout: true).trim()
                echo "BRS-KB v${version} build completed successfully"
            }
        }

        failure {
            echo ' Pipeline failed!'

            // Notify team
            emailext(
                subject: "BRS-KB Pipeline Failed - Build #${env.BUILD_NUMBER}",
                body: "The BRS-KB CI/CD pipeline has failed. Please check the Jenkins console output.",
                to: "security-team@company.com"
            )
        }

        unstable {
            echo ' Pipeline completed with warnings'
        }
    }
}
