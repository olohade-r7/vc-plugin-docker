"""
Main execution script for Fingerprinting Agent
Entry point for running the fingerprinting process
"""

import sys
import argparse
from fingerprinting_agent import FingerprintingAgent


def main():
    """Main execution function"""
    
    parser = argparse.ArgumentParser(
        description="System & Software Fingerprinting Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Local scan
  python main.py --local
  
  # Remote scan with SSH key
  python main.py --remote 192.168.1.100 --user admin --key ~/.ssh/id_rsa
  
  # Remote scan with password
  python main.py --remote 192.168.1.100 --user admin --password mypass
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
        # Create agent
        if args.local:
            print("\n[*] Initializing local fingerprinting agent...")
            agent = FingerprintingAgent(scan_type="local", target_host="localhost")
            
            # Run local scan
            agent.scan_local()
            
        else:  # Remote
            print(f"\n[*] Initializing remote fingerprinting agent...")
            agent = FingerprintingAgent(scan_type="remote", target_host=args.remote)
            
            # Run remote scan
            agent.scan_remote(
                hostname=args.remote,
                username=args.user,
                port=args.port,
                password=args.password,
                key_file=args.key
            )
        
        # Export report
        agent.export_report(args.output)
        
        # Print summary
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
