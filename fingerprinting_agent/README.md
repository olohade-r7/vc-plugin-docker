# Fingerprinting Agent - System & Software Scanner

Automated tool for detecting operating system details and installed software on local and remote machines.

---

## What is System Fingerprinting?

**Fingerprinting** is the process of identifying and cataloging system characteristics:
- Operating system type and version
- Installed software and their versions
- System hardware details

### Why Fingerprint Systems?

To assess vulnerabilities, you must first know **what software is installed**. A vulnerability in Docker v29.0 doesn't matter if Docker isn't installed, or if you have v30.0 (patched).

Fingerprinting creates a **software inventory** that the Scan Engine uses to check against known CVEs.

---

## How It Works

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  Target System   │     │  Run Detection   │     │   Generate       │
│  (Local/Remote)  │────▶│   Commands       │────▶│   JSON Report    │
│                  │     │  (via SSH/local) │     │                  │
└──────────────────┘     └──────────────────┘     └──────────────────┘
```

**Process:**
1. Connect to target (local subprocess or remote SSH)
2. Detect OS type (macOS, Linux, Windows)
3. Run OS-specific commands to find software
4. Parse version numbers from command output
5. Generate structured JSON report

---

## Usage

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
python main.py --remote 192.168.1.100 --user admin --password mypassword
```

### All Options
```bash
python main.py --help

Options:
  --local              Scan local machine
  --remote HOSTNAME    Scan remote machine via SSH
  --user USERNAME      SSH username (default: root)
  --password PASSWORD  SSH password
  --key KEYFILE        SSH private key path
  --port PORT          SSH port (default: 22)
  --output PATH        Output file path
```

---

## Output Format

**fingerprint_report.json:**
```json
{
  "agent_metadata": {
    "timestamp": "2026-01-16T10:00:00Z",
    "scan_type": "local",
    "target_host": "localhost"
  },
  "system_info": {
    "os": "macOS",
    "version": "26.2",
    "kernel": "25.2.0",
    "cpu": "Apple M4 Pro",
    "hostname": "my-laptop"
  },
  "software_inventory": [
    {
      "productName": "Docker",
      "versionNumber": "29.1.3",
      "vendor": "Docker Inc.",
      "productFamily": "Virtualization",
      "installPath": "/usr/local/bin/docker"
    },
    {
      "productName": "Chrome",
      "versionNumber": "144.0.7559",
      "vendor": "Google",
      "productFamily": "Browser",
      "installPath": "/Applications/Google Chrome.app"
    }
  ]
}
```

---

## Project Structure

```
fingerprinting_agent/
├── main.py                    # CLI entry point
├── fingerprinting_agent.py    # Main orchestrator
├── config.py                  # Software detection rules
├── models.py                  # Pydantic data models
│
├── modules/
│   ├── ssh_connector.py       # SSH connection handling
│   ├── evidence_collector.py  # Command execution
│   ├── system_info.py         # OS/CPU detection
│   └── software_fingerprinter.py  # Software detection
│
└── output/
    └── fingerprint_report.json
```

---

## Software Detection

### How Software is Detected

Each software has OS-specific detection commands defined in `config.py`:

```python
"Docker": {
    "vendor": "Docker Inc.",
    "productFamily": "Virtualization",
    "macOS": {
        "detection_command": "which docker 2>/dev/null",
        "version_command": "docker --version 2>/dev/null"
    },
    "Linux": {
        "detection_command": "which docker 2>/dev/null",
        "version_command": "docker --version 2>/dev/null"
    }
}
```

**Logic:**
1. Run `detection_command` - if output exists, software is installed
2. Run `version_command` - parse version from output
3. Record install path, vendor, family

### Currently Detected Software

| Software | Detection Method |
|----------|------------------|
| VS Code | Bundle identifier (macOS), `which code` (Linux) |
| Docker | `which docker` |
| Chrome | Bundle identifier (macOS), `which google-chrome` (Linux) |
| Slack | Bundle identifier (macOS) |
| Git | `which git` |
| Node.js | `which node` |
| Python | `which python3` |
| PyCharm | Bundle identifier (macOS) |

### Adding New Software

Edit `config.py`:
```python
TARGET_SOFTWARE = {
    "NewSoftware": {
        "vendor": "Vendor Name",
        "productFamily": "Category",
        "macOS": {
            "detection_command": "command to check if installed",
            "version_command": "command to get version"
        },
        "Linux": {
            "detection_command": "...",
            "version_command": "..."
        }
    }
}
```

---

## SSH Remote Scanning

### Prerequisites for Remote Scan

**On the target machine:**
1. SSH server must be running
2. You need valid credentials (password or key)
3. Network connectivity to the target

**For Linux targets:**
```bash
# Install SSH server
sudo apt install openssh-server
sudo systemctl start ssh
```

### How SSH Scanning Works

```
Your Machine                    Remote Machine
     │                               │
     │──── SSH Connect ─────────────▶│
     │                               │
     │◀─── Auth Success ─────────────│
     │                               │
     │──── uname -s ────────────────▶│  (detect OS)
     │◀─── "Linux" ──────────────────│
     │                               │
     │──── which docker ────────────▶│  (detect software)
     │◀─── "/usr/bin/docker" ────────│
     │                               │
     │──── docker --version ────────▶│  (get version)
     │◀─── "Docker version 24.0" ────│
```

---

## Evidence Collection

Every command execution is recorded as **evidence**:

```json
{
  "command_run": "docker --version",
  "raw_output": "Docker version 29.1.3, build abcd123",
  "execution_timestamp": "2026-01-16T10:00:00Z"
}
```

This provides:
- Audit trail of what was checked
- Raw data for debugging
- Proof of findings

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `paramiko` | SSH connections for remote scanning |
| `pydantic` | Data validation for reports |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| SSH connection failed | Check credentials, firewall, SSH service |
| Software not detected | Add detection rules to `config.py` |
| Version parsing error | Check `version_command` output format |
| Permission denied | Use sudo or check user permissions |

