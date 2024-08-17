def releaseTag
def newVersion

pipeline {
    agent any

    environment {
        DOCKER_CREDENTIALS_ID = 'docker_credentials'
        DOCKER_TAG = 'latest'
        GITHUB_CREDENTIALS_ID = 'github_token'
        GITHUB_REPO = 'cyse7125-su24-team16/project'
        DOCKER_HUB_REPO = '118a3025/csye_7125'
    }

    options {
        skipDefaultCheckout(true)
    }

    triggers {
        githubPush()
    }

    stages {
        stage('Checkout') {
            steps {
                script {
                    // Checkout the code
                    git credentialsId: GITHUB_CREDENTIALS_ID, url: "https://github.com/${env.GITHUB_REPO}.git", branch: 'main'
                }
            }
        }

        stage('Fetch and Checkout PR Branch') {
            when {
                expression {
                    return env.CHANGE_ID != null
                }
            }
            steps {
                script {
                    // Fetch the latest changes from the origin using credentials
                    withCredentials([usernamePassword(credentialsId: GITHUB_CREDENTIALS_ID, usernameVariable: 'GITHUB_USER', passwordVariable: 'GITHUB_TOKEN')]) {
                        sh 'git config --global credential.helper store'
                        sh 'echo "https://${GITHUB_USER}:${GITHUB_TOKEN}@github.com" > ~/.git-credentials'
                        // Fetch all branches including PR branches
                        sh 'git fetch origin +refs/pull/*/head:refs/remotes/origin/pr/*'
                        // Dynamically fetch the current PR branch name using environment variables
                        def prBranch = env.CHANGE_BRANCH
                        echo "PR Branch: ${prBranch}"
                        // Checkout the PR branch
                        sh "git checkout -B ${prBranch} origin/pr/${env.CHANGE_ID}"
                    }
                }
            }
        }

        stage('Check Commit Messages') {
            when {
                expression {
                    return env.CHANGE_ID != null
                }
            }
            steps {
                script {
                    // Fetch the latest commit message in the PR branch
                    def latestCommitMessage = sh(script: "git log -1 --pretty=format:%s", returnStdout: true).trim()
                    echo "Latest commit message: ${latestCommitMessage}"

                    // Regex for Conventional Commits
                    def pattern = ~/^\s*(feat|fix|docs|style|refactor|perf|test|chore)(\(.+\))?: .+\s*$/

                    // Check the latest commit message
                    if (!pattern.matcher(latestCommitMessage).matches()) {
                        error "Commit message does not follow Conventional Commits: ${latestCommitMessage}"
                    }
                }
            }
        }

        stage('Semantic-Release') {
            when {
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                script {
                    withCredentials([usernamePassword(credentialsId: GITHUB_CREDENTIALS_ID, usernameVariable: 'GITHUB_USER', passwordVariable: 'GITHUB_TOKEN')]) {
                        env.GIT_LOCAL_BRANCH = 'main'
                        def releaseOutput = sh(script: 'npx semantic-release --dry-run --json', returnStdout: true).trim()
                        def versionLine = releaseOutput.find(/Published release (\d+\.\d+\.\d+) on default channel/)

                        if (versionLine) {
                            // Extract the new version
                            newVersion = (versionLine =~ /(\d+\.\d+\.\d+)/)[0][0]
                            echo "New version: v${newVersion}"
                            
                            // Package code
                           sh "tar -czvf source-code-v${newVersion}.tar.gz --exclude='.git' --exclude='*.tar.gz' --exclude='*.zip' --ignore-failed-read ."

                            // Create GitHub release and upload the artifacts
                            sh """
                            gh release create v${newVersion} source-code-v${newVersion}.tar.gz \\
                            --repo ${env.GITHUB_REPO} \\
                            --title "Release v${newVersion}" \\
                            --notes "Automatically generated release by Jenkins pipeline."
                            rm source-code-v${newVersion}.tar.gz
                            """
                        } else {
                            error "Failed to capture the new version from semantic-release."
                        }
                    }
                }
            }
        }

        stage('Setup Buildx') {
            steps {
                script {
                    // Setup Buildx for multi-platform builds
                   sh '''
                    if docker buildx inspect mybuilder > /dev/null 2>&1; then
                        docker buildx rm mybuilder
                    fi

                    # Setup Buildx for multi-platform builds
                    docker run --privileged --rm tonistiigi/binfmt --install all
                    docker buildx create --use --name mybuilder --driver docker-container
                    docker buildx inspect mybuilder --bootstrap
                    '''
                }
            }
        }

        stage('Clean Docker') {
            steps {
                script {
                    // Clean up Docker space
                    sh 'docker system prune -af'
                    sh 'docker volume prune -f'
                }
            }
        }

     stage('Build and Push Docker Images') {
            when {
                allOf {
                    branch 'main'
                    not { changeRequest() }
                }
            }
            steps {
                script {
                    docker.withRegistry('https://index.docker.io/v1/', DOCKER_CREDENTIALS_ID) {
                        withEnv(["NEW_VERSION=${newVersion}"]) {
                            sh '''
                            docker run --privileged --rm tonistiigi/binfmt --install all
                        
                            # Setup Buildx
                            docker buildx create --use --name mybuilder --driver docker-container
                            docker buildx inspect mybuilder --bootstrap
                        
                            # Build and push the Flyway migration image
                            docker buildx build --builder mybuilder -f Dockerfile -t ${DOCKER_HUB_REPO}:streamlit-app-${NEW_VERSION} --platform "linux/arm64,linux/amd64" . --push

                            docker system prune -af
                            docker volume prune -f
                        
                            '''
                        }
                    }
                }
            }
        }

        stage('Clean Workspace') {
            steps {
                cleanWs()
            }
        }
    }

    post {
        failure {
            script {
                echo "Pipeline failed."
            }
        }
        success {
            script {
                echo "Pipeline succeeded."
            }
        }
    }
}