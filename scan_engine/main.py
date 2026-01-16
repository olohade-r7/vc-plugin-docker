"""
Vulnerability Scan Engine - Command Line Interface
===================================================
Run vulnerability scans from command line or start the web server.

Usage Examples:
---------------
# Run scan using default fingerprint file
python main.py --scan

# Run scan with custom fingerprint file
python main.py --scan --fingerprint /path/to/fingerprint.json

# Start web server
python main.py --web

# Show current configuration
python main.py --config

# Run fingerprinting agent first (local)
python main.py --fingerprint-local

# Run fingerprinting agent first (remote)
python main.py --fingerprint-remote 192.168.1.100 --user admin --password secret
"""

import sys
import os
import argparse
import json
import subprocess
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from engine import VulnerabilityScanner, run_scan
from config import (
    print_config, 
    get_fingerprint_path, 
    get_vck_content_dir,
    SCAN_RESULTS_FILE,
    FLASK_CONFIG,
    PROJECT_ROOT
)


def run_web_server():
    """Start the Flask web server"""
    from app import app
    
    print("\n" + "="*60)
    print("🌐 STARTING WEB DASHBOARD")
    print("="*60)
    print(f"Open in browser: http://{FLASK_CONFIG['HOST']}:{FLASK_CONFIG['PORT']}")
    print("Press Ctrl+C to stop")
    print("="*60 + "\n")
    
    app.run(
        host=FLASK_CONFIG['HOST'],
        port=FLASK_CONFIG['PORT'],
        debug=FLASK_CONFIG['DEBUG']
    )


def run_cli_scan(fingerprint_path: str = None, output_path: str = None):
    """Run vulnerability scan from CLI"""
    print("\n" + "="*60)
    print("🔍 VULNERABILITY SCAN ENGINE - CLI MODE")
    print("="*60)
    
    try:
        report = run_scan(fingerprint_path, output_path)
        
        # Print summary
        print("\n" + "-"*60)
        print("SCAN SUMMARY")
        print("-"*60)
        print(f"Scan ID:      {report['scan_id']}")
        print(f"Timestamp:    {report['timestamp']}")
        print(f"Total:        {report['summary']['total_software']} software items")
        print(f"Vulnerable:   {report['summary']['vulnerable_count']}")
        print(f"Secure:       {report['summary']['secure_count']}")
        
        # Print vulnerable items
        vulnerable = [r for r in report['results'] if r['status'] == 'VULNERABLE']
        if vulnerable:
            print("\n" + "-"*60)
            print("⚠️  VULNERABLE SOFTWARE:")
            print("-"*60)
            for item in vulnerable:
                print(f"  • {item['software']} v{item['installed']}")
                print(f"    CVE: {item['cve']} | Severity: {item['severity']}")
                print(f"    Solution: {item['solution']}")
                print()
        
        print(f"\n📄 Full report saved to: {SCAN_RESULTS_FILE}")
        return 0
        
    except FileNotFoundError as e:
        print(f"\n❌ Error: {e}")
        print("\n💡 Tip: Run fingerprinting first:")
        print("  python main.py --fingerprint-local")
        return 1
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return 1


def run_fingerprinting(remote: str = None, user: str = None, 
                       password: str = None, key: str = None, port: int = 22):
    """Run fingerprinting agent before scanning"""
    fingerprint_script = PROJECT_ROOT / "fingerprinting_agent" / "main.py"
    
    if not fingerprint_script.exists():
        print(f"❌ Fingerprinting agent not found at: {fingerprint_script}")
        return 1
    
    # Build command
    cmd = [sys.executable, str(fingerprint_script)]
    
    if remote:
        cmd.extend(["--remote", remote])
        if user:
            cmd.extend(["--user", user])
        if password:
            cmd.extend(["--password", password])
        if key:
            cmd.extend(["--key", key])
        if port != 22:
            cmd.extend(["--port", str(port)])
    else:
        cmd.append("--local")
    
    print(f"🔧 Running fingerprinting agent...")
    print(f"   Command: {' '.join(cmd)}")
    print()
    
    # Run fingerprinting
    result = subprocess.run(cmd, cwd=str(fingerprint_script.parent))
    return result.returncode


def main():
    parser = argparse.ArgumentParser(
        description="Vulnerability Scan Engine - Security Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run scan with default settings
  python main.py --scan
  
  # Run scan with custom fingerprint
  python main.py --scan --fingerprint /path/to/fingerprint.json
  
  # Start web dashboard
  python main.py --web
  
  # Run fingerprinting first, then scan
  python main.py --fingerprint-local
  python main.py --scan
  
  # Remote fingerprinting then scan
  python main.py --fingerprint-remote 192.168.1.100 --user admin --password secret
  python main.py --scan
        """
    )
    
    # Main action group
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--scan", 
        action="store_true",
        help="Run vulnerability scan"
    )
    action_group.add_argument(
        "--web", 
        action="store_true",
        help="Start web dashboard server"
    )
    action_group.add_argument(
        "--config", 
        action="store_true",
        help="Show current configuration"
    )
    action_group.add_argument(
        "--fingerprint-local", 
        action="store_true",
        help="Run fingerprinting agent on local system"
    )
    action_group.add_argument(
        "--fingerprint-remote", 
        metavar="HOST",
        help="Run fingerprinting agent on remote system via SSH"
    )
    
    # Scan options
    parser.add_argument(
        "--fingerprint", "-f",
        metavar="PATH",
        help="Path to fingerprint JSON file (for --scan)"
    )
    parser.add_argument(
        "--output", "-o",
        metavar="PATH",
        help="Output path for scan results JSON"
    )
    
    # Remote fingerprinting options
    parser.add_argument(
        "--user", "-u",
        default="root",
        help="SSH username (default: root)"
    )
    parser.add_argument(
        "--password", "-p",
        help="SSH password"
    )
    parser.add_argument(
        "--key", "-k",
        help="SSH private key file"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    
    args = parser.parse_args()
    
    # Execute action
    if args.config:
        print_config()
        return 0
    
    elif args.scan:
        return run_cli_scan(args.fingerprint, args.output)
    
    elif args.web:
        run_web_server()
        return 0
    
    elif args.fingerprint_local:
        ret = run_fingerprinting()
        if ret == 0:
            print("\n✅ Fingerprinting complete! Now run: python main.py --scan")
        return ret
    
    elif args.fingerprint_remote:
        ret = run_fingerprinting(
            remote=args.fingerprint_remote,
            user=args.user,
            password=args.password,
            key=args.key,
            port=args.port
        )
        if ret == 0:
            print("\n✅ Remote fingerprinting complete! Now run: python main.py --scan")
        return ret


if __name__ == "__main__":
    sys.exit(main())
