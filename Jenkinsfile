pipeline {
    agent any
    
    environment {
        TARGET_HOST = '192.168.11.107'  // Replace with your VM's IP
        SSH_USER = 'rb'
    }
    
    stages {
        stage('Test SSH Connection') {
            steps {
                sshagent(['vm-ssh-key']) {  // 'vm-ssh-key' is the ID you'll set in Jenkins credentials
                    script {
                        try {
                            sh """
                                ssh -o StrictHostKeyChecking=no ${SSH_USER}@${TARGET_HOST} 'echo "Connection successful! Current time is: \$(date)"'
                            """
                            echo "SSH connection successful!"
                        } catch (Exception e) {
                            error "Failed to connect via SSH: ${e.getMessage()}"
                        }
                    }
                }
            }
        }
        
        stage('Get System Info') {
            steps {
                sshagent(['vm-ssh-key']) {
                    script {
                        sh """
                            ssh -o StrictHostKeyChecking=no ${SSH_USER}@${TARGET_HOST} '
                                echo "===== System Information ====="
                                hostname
                                uname -a
                                ip addr show
                            '
                        """
                    }
                }
            }
        }
    }
    
    post {
        success {
            echo 'SSH connection test completed successfully!'
        }
        failure {
            echo 'SSH connection test failed!'
        }
    }
}