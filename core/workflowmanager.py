import asyncio
import logging
import random
from core.hostmanager import HostManager
from core.scanmanager import ScanManager


class WorkflowManager:
    """
    Manages dynamic workflows for handling scan results and integrating external tools.
    """

    def __init__(self, scan_manager: ScanManager):
        """
        Initialize the WorkflowManager.

        :param scan_manager: Instance of ScanManager to handle scans.
        """
        self.scan_manager = scan_manager
        self.hosts = {}
        self.logger = logging.getLogger("workflowmgr")
        self.logger.setLevel(logging.INFO)

    async def handle_dynamic_workflows(self, ip: str):
        """
        Handle dynamic workflows for a host based on its scan data and scan_config.json.

        :param ip: IP address of the host.
        """
        host = self.hosts[ip]

        for port in host.open_ports:
            service = host.services.get(port, "Unknown").lower()

            # Fetch the dynamic workflow from scan_config.json
            service_workflows = self.scan_manager.scan_config.get("service_workflows", {}).get(service, [])

            if not service_workflows:
                self.logger.info(f"No workflows defined for service {service} on {ip}:{port}.")
                continue

            self.logger.info(f"Executing workflows for {service} on {ip}:{port}.")

            for workflow in service_workflows:
                try:
                    workflow_type = workflow.get("type")
                    if workflow_type == "nse":
                        nse_script = workflow.get("script")
                        if nse_script:
                            self.logger.info(f"Running NSE script {nse_script} on {ip}:{port}.")
                            scan_id = await self.scan_manager.start_scan(
                                target=f"{ip}:{port}", scan_type="custom", options=f"--script {nse_script}"
                            )
                            result = await self.scan_manager.get_scan_results(scan_id)
                            host.update_from_scan(f"nse_{nse_script}", result)

                    elif workflow_type == "external_tool":
                        command = workflow.get("command").format(ip=ip, port=port)
                        self.logger.info(f"Running external tool: {command}")
                        result = await self.run_external_tool(command)
                        host.update_from_scan(f"external_{workflow.get('command').split()[0]}", result)

                    else:
                        self.logger.warning(f"Unsupported workflow type: {workflow_type} for service {service}.")

                except Exception as e:
                    self.logger.error(f"Error executing workflow for {service} on {ip}:{port}: {e}")

    async def run_external_tool(self, command: str) -> str:
        """
        Run an external tool asynchronously.

        :param command: The command to run.
        :return: The output from the tool.
        """
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            self.logger.error(f"Command failed with error: {stderr.decode()}")
            raise RuntimeError(f"Command failed: {stderr.decode()}")
        return stdout.decode()

    async def discover_hosts(self, subnet: str):
        """
        Discover hosts on a subnet using ScanManager.

        :param subnet: The subnet to scan (e.g., 192.168.1.0/24).
        """
        self.logger.info(f"Starting discovery scan on subnet: {subnet}")
        scan_id = await self.scan_manager.start_scan(target=subnet, scan_type="discovery")
        scan_results = await self.scan_manager.get_scan_results(scan_id)

        # Process discovered hosts
        for ip, details in scan_results.items():
            if details["status"] == "up":
                self.logger.info(f"Discovered live host: {ip}")
                self.hosts[ip] = HostManager(ip)

    async def perform_port_scan(self, ip: str):
        """
        Perform a port scan on a host.

        :param ip: IP address of the host.
        """
        self.logger.info(f"Performing port scan on host: {ip}")
        scan_id = await self.scan_manager.start_scan(target=ip, scan_type="port_scan")
        scan_results = await self.scan_manager.get_scan_results(scan_id)

        # Update host with port scan results
        host = self.hosts[ip]
        host.update_from_scan("port_scan", scan_results)

    async def run_workflow(self, subnet: str):
        """
        Run the entire workflow starting with discovery scan.

        :param subnet: The subnet to scan.
        """
        await self.discover_hosts(subnet)

        # Perform port scans for each live host
        for ip in list(self.hosts.keys()):
            await self.perform_port_scan(ip)

        # Handle dynamic workflows for each host
        for ip in list(self.hosts.keys()):
            await self.handle_dynamic_workflows(ip)