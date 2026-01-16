"""
Configuration for Fingerprinting Agent
Defines target software products and OS-specific detection commands
This is the "intelligence" - where we tell the agent what to look for and how
"""

# Target software products to fingerprint
# Each product has OS-specific commands to detect it
TARGET_SOFTWARE = {
    "PyCharm": {
        "vendor": "JetBrains",
        "productFamily": "IDE",
        "macOS": {
            "detection_command": "mdfind \"kMDItemCFBundleIdentifier == 'com.jetbrains.pycharm'\" 2>/dev/null | head -1",
            "version_command": "defaults read /Applications/PyCharm.app/Contents/Info CFBundleShortVersionString 2>/dev/null || echo 'unknown'",
            "install_path": "/Applications/PyCharm.app"
        },
        "Linux": {
            "detection_command": "which pycharm 2>/dev/null || find ~/.local/share/applications -name '*pycharm*' 2>/dev/null | head -1",
            "version_command": "pycharm --version 2>/dev/null || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where pycharm 2>nul || dir 'C:\\Program Files\\JetBrains\\PyCharm*' 2>nul",
            "version_command": "reg query 'HKLM\\Software\\JetBrains\\PyCharm' /v 'Install' 2>nul || echo unknown"
        }
    },
    "VS Code": {
        "vendor": "Microsoft",
        "productFamily": "IDE",
        "macOS": {
            "detection_command": "mdfind \"kMDItemCFBundleIdentifier == 'com.microsoft.VSCode'\" 2>/dev/null | head -1",
            "version_command": "/Applications/Visual\\ Studio\\ Code.app/Contents/Resources/app/bin/code --version 2>/dev/null | head -1 || echo 'unknown'",
            "install_path": "/Applications/Visual Studio Code.app"
        },
        "Linux": {
            "detection_command": "which code 2>/dev/null",
            "version_command": "code --version 2>/dev/null | head -1 || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where code 2>nul",
            "version_command": "reg query 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall' | findstr VSCode 2>nul"
        }
    },
    "Docker": {
        "vendor": "Docker Inc.",
        "productFamily": "Virtualization",
        "macOS": {
            "detection_command": "which docker 2>/dev/null",
            "version_command": "docker --version 2>/dev/null || echo 'unknown'",
            "install_path": "/Applications/Docker.app"
        },
        "Linux": {
            "detection_command": "which docker 2>/dev/null",
            "version_command": "docker --version 2>/dev/null || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where docker 2>nul",
            "version_command": "docker --version 2>nul || echo unknown"
        }
    },
    "Chrome": {
        "vendor": "Google",
        "productFamily": "Browser",
        "macOS": {
            "detection_command": "mdfind \"kMDItemCFBundleIdentifier == 'com.google.Chrome'\" 2>/dev/null | head -1",
            "version_command": "/Applications/Google\\ Chrome.app/Contents/MacOS/Google\\ Chrome --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'",
            "install_path": "/Applications/Google Chrome.app"
        },
        "Linux": {
            "detection_command": "which google-chrome 2>/dev/null || which chromium-browser 2>/dev/null",
            "version_command": "google-chrome --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where chrome 2>nul",
            "version_command": "reg query 'HKLM\\Software\\Google\\Chrome\\Binaries' /v Version 2>nul || echo unknown"
        }
    },
    "Slack": {
        "vendor": "Slack Technologies",
        "productFamily": "Communication",
        "macOS": {
            "detection_command": "mdfind \"kMDItemCFBundleIdentifier == 'com.tinyspeck.slackmacgap'\" 2>/dev/null | head -1",
            "version_command": "defaults read /Applications/Slack.app/Contents/Info CFBundleShortVersionString 2>/dev/null || echo 'unknown'",
            "install_path": "/Applications/Slack.app"
        },
        "Linux": {
            "detection_command": "which slack 2>/dev/null || find ~/.local -name 'slack' -type d 2>/dev/null | head -1",
            "version_command": "slack --version 2>/dev/null || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where slack 2>nul",
            "version_command": "reg query HKCU\\Software\\Slack /v Version 2>nul || echo unknown"
        }
    },
    "Git": {
        "vendor": "Git Project",
        "productFamily": "Development Tools",
        "macOS": {
            "detection_command": "which git 2>/dev/null",
            "version_command": "git --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'"
        },
        "Linux": {
            "detection_command": "which git 2>/dev/null",
            "version_command": "git --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where git 2>nul",
            "version_command": "git --version 2>nul | awk '{print $NF}' || echo unknown"
        }
    },
    "Node.js": {
        "vendor": "OpenJS Foundation",
        "productFamily": "Runtime",
        "macOS": {
            "detection_command": "which node 2>/dev/null",
            "version_command": "node --version 2>/dev/null | sed 's/^v//' || echo 'unknown'"
        },
        "Linux": {
            "detection_command": "which node 2>/dev/null",
            "version_command": "node --version 2>/dev/null | sed 's/^v//' || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where node 2>nul",
            "version_command": "node --version 2>nul || echo unknown"
        }
    },
    "Python": {
        "vendor": "Python Software Foundation",
        "productFamily": "Runtime",
        "macOS": {
            "detection_command": "which python3 2>/dev/null",
            "version_command": "python3 --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'"
        },
        "Linux": {
            "detection_command": "which python3 2>/dev/null",
            "version_command": "python3 --version 2>/dev/null | awk '{print $NF}' || echo 'unknown'"
        },
        "Windows": {
            "detection_command": "where python 2>nul",
            "version_command": "python --version 2>nul || echo unknown"
        }
    }
}

# =============================================================================
# AUTO-DISCOVERY CONFIGURATION
# =============================================================================
# Commands to discover ALL installed software on the system
# This is optional - used when --discover flag is passed

AUTO_DISCOVERY_CONFIG = {
    "enabled": False,  # Set to True to enable auto-discovery by default
    "macOS": {
        # List all GUI applications
        "list_apps": "ls /Applications/*.app 2>/dev/null | xargs -n1 basename 2>/dev/null | sed 's/.app$//'",
        # List all homebrew packages
        "list_brew": "brew list --versions 2>/dev/null",
        # List all command-line tools with versions
        "list_cli": """
            for cmd in docker git node npm python3 ruby java go rust cargo pip3 aws kubectl terraform ansible; do
                if which $cmd >/dev/null 2>&1; then
                    version=$($cmd --version 2>&1 | head -1)
                    echo "$cmd|$version"
                fi
            done
        """,
    },
    "Linux": {
        # List installed packages (Debian/Ubuntu)
        "list_apt": "dpkg -l 2>/dev/null | grep '^ii' | awk '{print $2\"|\"$3}'",
        # List installed packages (RHEL/CentOS/Fedora)
        "list_rpm": "rpm -qa --qf '%{NAME}|%{VERSION}\\n' 2>/dev/null",
        # List snap packages
        "list_snap": "snap list 2>/dev/null | tail -n +2 | awk '{print $1\"|\"$2}'",
        # List flatpak packages
        "list_flatpak": "flatpak list --app 2>/dev/null | awk -F'\\t' '{print $1\"|\"$2}'",
        # List common CLI tools
        "list_cli": """
            for cmd in docker git node npm python3 ruby java go rust cargo pip3 aws kubectl terraform ansible; do
                if which $cmd >/dev/null 2>&1; then
                    version=$($cmd --version 2>&1 | head -1)
                    echo "$cmd|$version"
                fi
            done
        """,
    },
    "Windows": {
        # List installed programs from registry
        "list_programs": "wmic product get name,version /format:csv 2>nul",
        # List from PowerShell
        "list_powershell": "powershell \"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Format-Table -HideTableHeaders\"",
    }
}

# System info detection commands (platform-specific)
SYSTEM_INFO_COMMANDS = {
    "macOS": {
        "os_name": ("system_profiler SPSoftwareDataType | grep 'System Version' | awk -F: '{print $2}' | awk '{print $1}'", "macOS"),
        "os_version": ("sw_vers -productVersion", None),  # Extract version only
        "kernel": ("uname -r", None),
        "cpu": ("sysctl -n machdep.cpu.brand_string", None),
        "cpu_arch": ("uname -m", None),
        "hostname": ("hostname", None)
    },
    "Linux": {
        "os_name": ("lsb_release -si 2>/dev/null || cat /etc/os-release | grep '^NAME=' | cut -d'=' -f2 | tr -d '\"'", None),
        "os_version": ("lsb_release -sr 2>/dev/null || cat /etc/os-release | grep '^VERSION_ID=' | cut -d'=' -f2 | tr -d '\"'", None),
        "kernel": ("uname -r", None),
        "cpu": ("cat /proc/cpuinfo | grep 'model name' | head -1 | awk -F: '{print $2}' | xargs", None),
        "cpu_arch": ("uname -m", None),
        "hostname": ("hostname", None)
    },
    "Windows": {
        "os_name": ("wmic os get caption /value 2>nul | findstr /I caption", "Windows"),
        "os_version": ("wmic os get version /value 2>nul | findstr /I version", None),
        "kernel": ("ver", None),
        "cpu": ("wmic cpu get name /value 2>nul | findstr /I name", None),
        "cpu_arch": ("wmic os get osarchitecture /value 2>nul | findstr /I osarchitecture", None),
        "hostname": ("hostname", None)
    }
}

# SSH Connection defaults
SSH_CONFIG = {
    "timeout": 30,
    "port": 22,
    "auth_type": "key"  # Can be 'key' or 'password'
}

# Output settings
OUTPUT_CONFIG = {
    "report_filename": "fingerprint_report.json",
    "output_dir": "./output",
    "pretty_print": True,
    "indent": 2
}
