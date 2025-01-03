import os
import asyncio
import yaml
from nmap3 import NmapAsync
from utils.logger import create_logger
from core.hosts import Host

class ScanManager:
    def __init__(self, results_dir="results"):
        """
        Initialize the ScanManager with an NmapAsync instance, logger, and results directory.

        Args:
            results_dir (str): Directory to save scan results.
        """
        self.logger = create_logger("scan_manager", "logs/scan_manager.log")
        self.nmap_async = NmapAsync()
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)

    async def run_discovery_scan(self, target_cidr):
        """
        Run a discovery scan and display the output directly in the terminal.

        Args:
            target_cidr (str): The CIDR range to scan.

        Returns:
            None
        """
        self.logger.info(f"Starting discovery scan on: {target_cidr}")

        # Load scan configuration
        try:
            with open("config/scan_config.yaml", "r") as file:
                scan_config = yaml.safe_load(file)
        except Exception as e:
            self.logger.error(f"Failed to load scan configuration: {e}")
            return

        # Get discovery scan command from config
        try:
            discovery_command = scan_config["discovery"]["command"]
            process_command = discovery_command.format(target_cidr=target_cidr)
        except KeyError as e:
            self.logger.error(f"Missing discovery scan configuration: {e}")
            return

        self.logger.info(f"Discovery scan command: {process_command}")

        # Run the discovery scan with the dynamically built command
        process = await asyncio.create_subprocess_shell(
            f"nmap {process_command}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # Stream stdout and stderr to terminal in real-time
        async for line in process.stdout:
            print(line.decode().strip())

        async for line in process.stderr:
            print(line.decode().strip())

        await process.wait()
        self.logger.info("Discovery scan completed.")

    async def run_service_scan(self, host):
        """
        Run a service scan on a specific host.

        Args:
            host (Host): The host to scan.

        Returns:
            dict: Parsed results of the service scan.
        """
        sanitized_target = host.ip.replace(".", "_")
        output_file = os.path.join(self.results_dir, f"{sanitized_target}_service_scan.xml")

        self.logger.info(f"Starting service scan on: {host.ip}")
        try:
            # Run service scan with the output saved to a file
            results = await self.nmap_async.scan_command(
                host.ip, arg=f"-p- -sV -O -oX {output_file}"
            )

            # Add scan results to the host instance
            host.scans_completed.append("service_scan")
            host.scan_results["service_scan"] = results

            self.logger.info(f"Service scan completed successfully for {host.ip}.")
            return results
        except Exception as e:
            self.logger.error(f"Error during service scan on {host.ip}: {e}")
            return None