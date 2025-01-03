import os
import psutil
import socket
import ipaddress
from utils.logger import create_logger
from config.config import RESULTS_DIR

logger = create_logger("stager", "logs/stager.log")

def create_dir_structure():
    """
    Create the directory structure required for storing results.
    """
    os.makedirs(RESULTS_DIR, exist_ok=True)


def get_interfaces_and_subnets():
    """
    Retrieve available network interfaces and their IPv4 subnets.

    Returns:
        list: A list of tuples containing the interface name and its subnet.
    """
    interfaces_with_subnets = []
    addresses = psutil.net_if_addrs()

    for iface, addr_list in addresses.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET:  # Only consider IPv4 addresses
                try:
                    ip = ipaddress.IPv4Interface(f"{addr.address}/{addr.netmask}")
                    interfaces_with_subnets.append((iface, str(ip.network)))
                except ValueError:
                    pass  # Skip invalid addresses
    return interfaces_with_subnets

def get_subnet_choice():
    """
    Display available interfaces with subnets and allow the user to select one.

    Returns:
        tuple: The selected interface name and subnet in CIDR notation, or None if no selection is made.
    """
    interfaces_with_subnets = get_interfaces_and_subnets()

    if not interfaces_with_subnets:
        print("No network interfaces with IPv4 subnets available.")
        logger.error("No network interfaces with IPv4 subnets available.")
        return None

    print("Available network interfaces and subnets:")
    for i, (iface, subnet) in enumerate(interfaces_with_subnets, start=1):
        print(f"{i}. {iface} - {subnet}")

    while True:
        try:
            choice = int(input("Select a network interface by number: "))
            if 1 <= choice <= len(interfaces_with_subnets):
                selected = interfaces_with_subnets[choice - 1]
                logger.info(f"Selected interface: {selected[0]}, Subnet: {selected[1]}")
                return selected
            else:
                print("Invalid choice. Please select a valid number.")
        except ValueError:
            print("Invalid input. Please enter a number.")

def stage_discovery():
    """
    Handle the discovery stage by allowing the user to select a network interface and subnet.

    Returns:
        tuple: The selected interface and subnet, or None if no valid selection is made.
    """
    result = get_subnet_choice()
    if result:
        print(f"Selected interface: {result[0]}, Subnet: {result[1]}")
        return result
    else:
        print("No valid interface selected.")
        logger.error("No valid interface selected during discovery.")
        return None

def handle_options(target_input):
    """
    Validate and process the target input provided via the `-t` option.

    Args:
        target_input (list): A list of target strings (e.g., IPs or CIDR).

    Returns:
        list: A list of validated targets (IP or CIDR).
    """
    targets = []
    for target in target_input:
        try:
            # Check if target is a valid IP or CIDR
            ip = ipaddress.ip_network(target, strict=False)
            targets.append(str(ip))
        except ValueError:
            logger.error(f"Invalid target format: {target}")
            raise ValueError(f"Invalid target format: {target}")
    logger.info(f"Validated targets: {targets}")
    return targets

def determine_target(args):
    """
    Determine the scanning target based on program arguments or interactive selection.

    Args:
        args (argparse.Namespace): Parsed command-line arguments.

    Returns:
        list: A list of targets (IP or CIDR) for scanning.
    """
    if args.target:
        # Validate targets provided via the `-t` option
        try:
            targets = handle_options(args.target)
            logger.info(f"Targets specified via command line: {targets}")
            return targets
        except ValueError as e:
            logger.error(f"Invalid target: {e}")
            print(f"Error: {e}")
            exit(1)
    else:
        # Fallback to interactive selection
        result = stage_discovery()
        if result:
            return [result[1]]  # Return only the subnet
        else:
            logger.error("No valid target or subnet selected.")
            print("Error: No valid target or subnet selected. Exiting.")
            exit(1)

def sanitize_target(target):
    """
    Sanitize and validate an IPv4 target.

    Args:
        target (str): The target string to sanitize.

    Returns:
        str: A sanitized IPv4 address.

    Raises:
        ValueError: If the target is not a valid IPv4 address.
    """
    # Strip unwanted characters (e.g., parentheses, spaces)
    stripped_target = target.strip("() ").strip()

    try:
        # Validate and return the sanitized IPv4 address
        ip = ipaddress.IPv4Address(stripped_target)
        return str(ip)
    except ipaddress.AddressValueError:
        raise ValueError(f"Invalid IPv4 address: {target}")