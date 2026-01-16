import sys
import argparse
from fingerprinting_agent import FingerprintingAgent


def main():
    
    parser = argparse.ArgumentParser(
        description="System & Software Fingerprinting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local scan (predefined software only)
  python main.py --local
  
  # Local scan with auto-discovery (ALL software)
  python main.py --local --discover
  
  # Remote scan with SSH key
  python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
  
  # Remote scan with password
  python main.py --remote 192.168.1.100 --user admin --password mypass
  
  # Remote scan with discovery mode
  python main.py --remote 192.168.1.100 --user admin --password mypass --discover
        """
    )
    
    # Scan type arguments
    scan_group = parser.add_mutually_exclusive_group(required=True)
    scan_group.add_argument(
        "--local",
        action="store_true",
        help="Run local fingerprinting scan"
    )
    scan_group.add_argument(
        "--remote",
        metavar="HOSTNAME",
        help="Run remote fingerprinting scan via SSH"
    )
    
    # Discovery mode
    parser.add_argument(
        "--discover",
        action="store_true",
        help="Enable auto-discovery mode: detect ALL installed software (not just predefined). "
             "This scans applications, packages (brew/apt/rpm), and CLI tools."
    )
    
    # Remote scan options
    parser.add_argument(
        "--user",
        default="root",
        help="SSH username (default: root)"
    )
    parser.add_argument(
        "--password",
        help="SSH password (if not using key)"
    )
    parser.add_argument(
        "--key",
        help="SSH private key file path"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=22,
        help="SSH port (default: 22)"
    )
    parser.add_argument(
        "--output",
        default="output/fingerprint_report.json",
        help="Output JSON file path (default: output/fingerprint_report.json)"
    )
    
    args = parser.parse_args()
    
    try:
        if args.local:
            print("\n[*] Initializing local fingerprinting agent...")
            if args.discover:
                print("[*] Discovery mode ENABLED - scanning ALL software")
            agent = FingerprintingAgent(
                scan_type="local", 
                target_host="localhost",
                discover_all=args.discover
            )
            agent.scan_local()
            
        else:
            print(f"\n[*] Initializing remote fingerprinting agent...")
            if args.discover:
                print("[*] Discovery mode ENABLED - scanning ALL software")
            agent = FingerprintingAgent(
                scan_type="remote", 
                target_host=args.remote,
                discover_all=args.discover
            )
            agent.scan_remote(
                hostname=args.remote,
                username=args.user,
                port=args.port,
                password=args.password,
                key_file=args.key
            )
        
        agent.export_report(args.output)
        agent.print_report_summary()
        
        print("[✓] Fingerprinting complete!")
        return 0
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
