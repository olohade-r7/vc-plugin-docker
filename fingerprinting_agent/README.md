# Fingerprinting Agent - README

## Overview
A Python-based system fingerprinting agent that detects OS details and installed software with full evidence tracking.

## Project Structure

```
fingerprinting_agent/
├── main.py                          # Entry point
├── fingerprinting_agent.py           # Main orchestrator
├── models.py                         # Pydantic data models
├── config.py                         # Configuration and target software
├── requirements.txt                  # Dependencies
├── modules/
│   ├── evidence_collector.py        # Command execution and evidence tracking
│   ├── system_info.py               # OS and system detection
│   ├── software_fingerprinter.py    # Software detection and metadata extraction
│   └── ssh_connector.py             # Remote SSH connections
└── output/
    └── fingerprint_report.json       # Generated report (created after scan)
```

## Architecture

### 1. **Models (models.py)**
- Pydantic models for type-safe data structures
- Defines JSON output schema
- Ensures data integrity before export

### 2. **Configuration (config.py)**
- Lists target software products to detect
- OS-specific commands for each software
- System information extraction commands
- Platform-aware (macOS, Linux, Windows)

### 3. **Evidence Collector (modules/evidence_collector.py)**
- Executes shell commands (local and remote)
- Captures stdout, stderr, return codes
- Tracks execution history for audit trail
- **WHY**: Ensures all findings are verifiable

### 4. **System Info Detector (modules/system_info.py)**
- Detects OS, version, kernel, CPU
- Platform-aware execution
- Returns structured system information
- **WHY**: Foundation for understanding target environment

### 5. **Software Fingerprinter (modules/software_fingerprinter.py)**
- Detects installed applications
- Extracts version numbers intelligently
- Identifies installation paths
- Determines architecture (arm64, x86_64)
- **WHY**: Core intelligence for vulnerability matching

### 6. **SSH Connector (modules/ssh_connector.py)**
- Handles remote SSH connections
- Supports key and password authentication
- Uses subprocess (preferred) or paramiko (fallback)
- **WHY**: Enables remote scanning without local access

### 7. **Fingerprinting Agent (fingerprinting_agent.py)**
- Orchestrates entire scanning process
- Supports local and remote modes
- Assembles final JSON report
- **WHY**: Central controller that ties everything together

### 8. **Main Entry Point (main.py)**
- Command-line interface
- Arguments parsing
- Handles user input for local/remote scans
- Exports report to JSON file

## Usage

### Local Scan
```bash
cd fingerprinting_agent
python main.py --local
```

### Remote Scan (with SSH key)
```bash
python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
```

### Remote Scan (with password)
```bash
python main.py --remote 192.168.1.100 --user admin --password mypass
```

### Custom Output Path
```bash
python main.py --local --output /path/to/fingerprint_report.json
```

## Output Format

The generated `fingerprint_report.json` contains:

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

**Issue**: Command timeouts  
**Solution**: Increase timeout in config or check system performance

**Issue**: SSH connection failed  
**Solution**: Verify credentials, SSH key permissions (600), firewall rules

**Issue**: Software not detected  
**Solution**: Check if command is in config.py, ensure software is installed

## Future Enhancements

- [ ] Remote scanning implementation
- [ ] Custom software detection rules
- [ ] Database export options
- [ ] Scheduled scanning
- [ ] Comparison between scans (delta reporting)
- [ ] Performance optimizations for large environments
