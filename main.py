import argparse
import asyncio
from core.scan_manager import ScanManager
from utils.stager import create_dir_structure, determine_target

async def main():
    """
    Main entry point for the program.
    """
    # Parse arguments
    parser = argparse.ArgumentParser(description="Network Enumeration Tool")
    parser.add_argument(
        "-t", "--target", nargs="+", help="Specify target(s): IP, CIDR, or list of IPs."
    )
    args = parser.parse_args()

    # Create required directories
    create_dir_structure()

    # Determine the target
    try:
        targets = determine_target(args)
    except SystemExit:
        return  # Exit cleanly if the user exits during selection

    # Initialize ScanManager
    scan_manager = ScanManager()

    # Run discovery scan for each target
    for target in targets:
        try:
            await scan_manager.run_discovery_scan(target)
        except Exception as e:
            print(f"Error during scan for target {target}: {e}")
            break  # Stop further processing on error

    print("Discovery scans completed. Exiting.")

if __name__ == "__main__":
    asyncio.run(main())

