"""
SSH Connector Module
Handles remote system connections and command execution
WHY: Allows fingerprinting of remote machines without direct access
"""

from typing import Tuple, Optional, Dict, Any
import subprocess
import json


class SSHConnector:
    """
    Manages SSH connections to remote systems
    Supports both password and key-based authentication
    """
    
    def __init__(
        self,
        hostname: str,
        username: str,
        port: int = 22,
        password: Optional[str] = None,
        key_file: Optional[str] = None,
        timeout: int = 30
    ):
        """
        Initialize SSH connection parameters
        
        Args:
            hostname: Remote host IP or domain
            username: SSH username
            port: SSH port (default 22)
            password: Password for authentication
            key_file: Path to SSH private key
            timeout: Connection timeout in seconds
        """
        self.hostname = hostname
        self.username = username
        self.port = port
        self.password = password
        self.key_file = key_file
        self.timeout = timeout
        self.connection = None
        self._use_paramiko = self._check_paramiko_available()
    
    def _check_paramiko_available(self) -> bool:
        """Check if paramiko is available for SSH connections"""
        try:
            import paramiko
            return True
        except ImportError:
            return False
    
    def connect_with_subprocess(self) -> bool:
        """
        Test connection using subprocess/ssh command
        This is the preferred method as requested in requirements
        
        Returns:
            True if connection successful
        """
        try:
            # Build SSH command
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=" + str(self.timeout),
                "-o", "StrictHostKeyChecking=no",
                "-p", str(self.port),
            ]
            
            # Add authentication
            if self.key_file:
                ssh_cmd.extend(["-i", self.key_file])
            
            ssh_cmd.append(f"{self.username}@{self.hostname}")
            ssh_cmd.append("echo 'SSH Connection Test'")
            
            # Test connection
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return result.returncode == 0
            
        except Exception as e:
            print(f"SSH connection test failed: {str(e)}")
            return False
    
    def connect_with_paramiko(self) -> bool:
        """
        Connect using paramiko library (fallback)
        
        Returns:
            True if connection successful
        """
        if not self._use_paramiko:
            return False
        
        try:
            import paramiko
            
            self.connection = paramiko.SSHClient()
            self.connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.key_file:
                self.connection.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_file,
                    timeout=self.timeout
                )
            else:
                self.connection.connect(
                    hostname=self.hostname,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=self.timeout
                )
            
            return True
            
        except Exception as e:
            print(f"Paramiko connection failed: {str(e)}")
            return False
    
    def execute_command(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute command on remote system via SSH subprocess
        
        Args:
            command: Command to execute
            
        Returns:
            (success, stdout, stderr)
        """
        try:
            ssh_cmd = [
                "ssh",
                "-o", "ConnectTimeout=" + str(self.timeout),
                "-o", "StrictHostKeyChecking=no",
                "-p", str(self.port),
            ]
            
            if self.key_file:
                ssh_cmd.extend(["-i", self.key_file])
            
            ssh_cmd.append(f"{self.username}@{self.hostname}")
            ssh_cmd.append(command)
            
            result = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            
            return (
                result.returncode == 0,
                result.stdout.strip(),
                result.stderr.strip()
            )
            
        except subprocess.TimeoutExpired:
            return (False, "", f"Command timeout after {self.timeout}s")
        except Exception as e:
            return (False, "", str(e))
    
    def execute_command_with_paramiko(self, command: str) -> Tuple[bool, str, str]:
        """
        Execute command using existing paramiko connection
        
        Args:
            command: Command to execute
            
        Returns:
            (success, stdout, stderr)
        """
        if not self.connection:
            return (False, "", "No active connection")
        
        try:
            stdin, stdout, stderr = self.connection.exec_command(
                command,
                timeout=self.timeout
            )
            
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            return (len(error) == 0, output, error)
            
        except Exception as e:
            return (False, "", str(e))
    
    def disconnect(self):
        """Close SSH connection"""
        if self.connection:
            try:
                self.connection.close()
                print(f"Disconnected from {self.hostname}")
            except Exception as e:
                print(f"Error closing connection: {str(e)}")
    
    def get_connection_info(self) -> Dict[str, Any]:
        """Get connection details"""
        return {
            "hostname": self.hostname,
            "username": self.username,
            "port": self.port,
            "auth_type": "key" if self.key_file else "password",
            "timeout": self.timeout
        }
