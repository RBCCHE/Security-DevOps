pipeline {
    agent any
    
    environment {
        REMOTE_HOST = 'your_remote_ip_or_hostname'  // Replace with your remote server IP or hostname
        REMOTE_USER = 'your_ssh_user'              // Replace with your SSH username
        SSH_PRIVATE_KEY = credentials('your-ssh-private-key-id')  // Replace with your Jenkins SSH credential ID
    }

    stages {
        stage('SSH to Remote Server') {
            steps {
                script {
                    // Use ssh-agent to handle the SSH key securely
                    sshagent (credentials: [SSH_PRIVATE_KEY]) {
                        // Run the SSH command on the remote server
                        sh """
                            ssh -o StrictHostKeyChecking=no ${REMOTE_USER}@${REMOTE_HOST} 'hostname'
                        """
                    }
                }
            }
        }
    }
    
    post {
        always {
            echo 'SSH command execution completed.'
        }
    }
}
