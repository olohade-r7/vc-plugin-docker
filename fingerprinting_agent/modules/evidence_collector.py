"""
Evidence Collector Module
Captures command execution history for audit trail and verification
WHY: Every data point must be traceable to its source for security auditing
"""

from typing import Dict, Tuple, Optional
from datetime import datetime
import subprocess


class EvidenceCollector:
    """
    Tracks all commands executed and their raw outputs
    This ensures data integrity and allows verification of findings
    """
    
    def __init__(self):
        self.evidence_log: Dict[str, Dict] = {}
        self.execution_errors: list = []
    
    def execute_command_locally(
        self,
        command: str,
        description: str = "",
        shell: bool = True,
        timeout: int = 10
    ) -> Tuple[bool, str, str]:
        """
        Execute a shell command locally and capture evidence
        
        Args:
            command: Shell command to execute
            description: Human-readable description of what we're doing
            shell: Whether to run through shell (True) or direct execution (False)
            timeout: Maximum execution time in seconds
            
        Returns:
            (success, stdout, stderr)
        """
        
        try:
            result = subprocess.run(
                command,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            output = result.stdout.strip() if result.stdout else ""
            error = result.stderr.strip() if result.stderr else ""
            
            # Store evidence
            self.evidence_log[description] = {
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "raw_output": output,
                "return_code": result.returncode,
                "error": error if error else None
            }
            
            return (result.returncode == 0, output, error)
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timeout after {timeout}s: {command}"
            self.execution_errors.append(error_msg)
            self.evidence_log[description] = {
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": error_msg,
                "raw_output": ""
            }
            return (False, "", error_msg)
            
        except Exception as e:
            error_msg = f"Command execution failed: {str(e)}"
            self.execution_errors.append(error_msg)
            self.evidence_log[description] = {
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": error_msg,
                "raw_output": ""
            }
            return (False, "", error_msg)
    
    def execute_command_remote(
        self,
        ssh_connection,
        command: str,
        description: str = "",
        timeout: int = 10
    ) -> Tuple[bool, str, str]:
        """
        Execute command on remote system via SSH
        
        Args:
            ssh_connection: Active SSH connection object
            command: Command to execute on remote
            description: What we're doing
            timeout: Execution timeout
            
        Returns:
            (success, stdout, stderr)
        """
        try:
            stdin, stdout, stderr = ssh_connection.exec_command(command, timeout=timeout)
            output = stdout.read().decode('utf-8').strip()
            error = stderr.read().decode('utf-8').strip()
            
            # Store evidence
            self.evidence_log[description] = {
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "raw_output": output,
                "error": error if error else None,
                "remote": True
            }
            
            return (len(error) == 0, output, error)
            
        except Exception as e:
            error_msg = f"Remote command failed: {str(e)}"
            self.execution_errors.append(error_msg)
            self.evidence_log[description] = {
                "command": command,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "error": error_msg,
                "raw_output": "",
                "remote": True
            }
            return (False, "", error_msg)
    
    def get_evidence(self, key: str) -> Optional[Dict]:
        """Retrieve evidence for a specific command"""
        return self.evidence_log.get(key)
    
    def get_all_evidence(self) -> Dict:
        """Return all collected evidence"""
        return self.evidence_log
    
    def has_errors(self) -> bool:
        """Check if any errors occurred"""
        return len(self.execution_errors) > 0
    
    def get_errors(self) -> list:
        """Get list of all errors"""
        return self.execution_errors
