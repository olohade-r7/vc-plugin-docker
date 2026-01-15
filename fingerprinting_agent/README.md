# Fingerprinting Agent - System & Software Scanner

System fingerprinting tool for detecting OS details and installed software on local and remote machines via SSH.

## 🎯 Purpose

Identifies system specifications, installed software versions, and configurations to support vulnerability assessment and inventory management.

## 🏗 Architecture

```
SSH Connector       → Remote authentication
    ↓
Evidence Collector  → Execute commands
    ↓
System Detector     → OS, kernel, CPU info
    ↓
Software Fingerprinter → Detect installed apps
    ↓
JSON Report         → Structured output
```

## 📦 Components

| Component | Purpose |
|-----------|---------|
| `main.py` | CLI entry point |
| `fingerprinting_agent.py` | Orchestrator |
| `models.py` | Pydantic data models |
| `config.py` | Software detection configs |
| `modules/ssh_connector.py` | Remote SSH connections |
| `modules/evidence_collector.py` | Command execution |
| `modules/system_info.py` | OS/system detection |
| `modules/software_fingerprinter.py` | Software detection |

## 🚀 Usage

### Local Scan
```bash
cd fingerprinting_agent
python main.py --local
```

### Remote Scan (SSH Key)
```bash
python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
```

### Remote Scan (Password)
```bash
python main.py --remote 192.168.1.100 --user admin --password mypass
```

### Custom Output
```bash
python main.py --local --output custom_report.json
```

## 📤 Output

`output/fingerprint_report.json`:

```json
{
  "agent_metadata": {
    "scan_type": "local",
    "target_host": "localhost",
    "timestamp": "2026-01-15T10:30:00Z"
  },
  "system_info": {
    "os": "macOS",
    "version": "14.2.1",
    "kernel": "23.3.0",
    "cpu": "Apple M1",
    "hostname": "MacBook-Pro.local"
  },
  "software_inventory": [
    {
      "name": "Docker",
      "version": "24.0.6",
      "path": "/usr/local/bin/docker",
      "architecture": "arm64",
      "detection_evidence": "..."
    }
  ],
  "summary": {
    "total_software_detected": 12,
    "execution_status": "success"
  }
}
```

## 🔧 Configuration

Edit [config.py](config.py) to add/modify software detection:

```python
TARGET_SOFTWARE = {
    "Docker": {
        "macos": ["docker --version"],
        "linux": ["docker --version", "which docker"]
    }
}
```

## 📊 Detection Features

- **System Information**: OS, version, kernel, CPU, hostname
- **Software Detection**: Version, path, architecture
- **Evidence Tracking**: Commands, outputs, return codes
- **Multi-platform**: macOS, Linux, Windows support
- **Remote Scanning**: SSH key and password auth

## 🛠 Dependencies

```
paramiko>=3.0.0
pydantic>=2.0.0
```

Install: `pip install -r requirements.txt`

## 🔐 SSH Requirements

For remote scans:
1. SSH server running on target
2. Valid credentials (key or password)
3. Network connectivity
4. User permissions to execute commands

```json
{
  "agent_metadata": {
    "timestamp": "2026-01-15T10:00:00Z",
    "scan_type": "local",
    "target_host": "localhost"
  },
  "system_info": {
    "os": "macOS",
    "version": "14.2.1",
    "kernel": "23.2.0",
    "cpu": "Apple M2",
    "hostname": "MacBook-Pro"
  },
  "software_inventory": [
    {
      "productName": "Python",
      "versionNumber": "3.11.0",
      "architecture": "arm64",
      "productFamily": "Runtime",
      "vendor": "Python Software Foundation",
      "installPath": "/usr/local/bin/python3",
      "evidence": {
        "command_run": "which python3",
        "raw_output": "/usr/local/bin/python3"
      }
    }
  ],
  "summary": {
    "total_software_detected": 8,
    "scan_type": "local",
    "execution_status": "success"
  }
}
```

## Data Integrity

Every piece of data includes:
- **Command Executed**: Exact shell command used
- **Raw Output**: Unmodified system output
- **Execution Timestamp**: When the command ran
- **Return Code**: Success/failure indicator

This ensures findings can be verified and audited.

## Supported Platforms

- **macOS** (all commands optimized)
- **Linux** (Ubuntu, Debian, RHEL, etc.)
- **Windows** (CMD/PowerShell commands)

## Supported Software

Currently fingerprints:
- PyCharm (JetBrains)
- VS Code (Microsoft)
- Docker (Docker Inc.)
- Chrome (Google)
- Slack (Slack Technologies)
- Git (Git Project)
- Node.js (OpenJS Foundation)
- Python (Python Software Foundation)

## Adding New Software

Edit `config.py` and add to `TARGET_SOFTWARE`:

```python
"Software Name": {
    "vendor": "Vendor Name",
    "productFamily": "Category",
    "macOS": {
        "detection_command": "command to find it",
        "version_command": "command to get version"
    },
    "Linux": { ... },
    "Windows": { ... }
}
```

## Integration with Vulnerability Scanner

This fingerprint report feeds into the vulnerability scanner:

1. **Fingerprinter** → `fingerprint_report.json` (What's installed?)
2. **Scanner** → Compares with `all_vulnerabilities.json` (What vulnerabilities?)
3. **Reporter** → Generates alerts (What needs to be fixed?)

## Troubleshooting

**Issue**: SSH connection failed  
**Solution**: Verify credentials, SSH key permissions (600), firewall rules

**Issue**: Software not detected  
**Solution**: Check if command is in config.py, ensure software is installed

