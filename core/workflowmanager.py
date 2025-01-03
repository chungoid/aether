import asyncio
import os
import json
from core.scanmanager import ScanManager
from core.hostmanager import HostManager
from config.config import NSE_CONFIG_PATH


class Phase:
    def __init__(self, phase_name, workflow_manager_instance):
        self.phase_name = phase_name
        self.workflow_manager_instance = workflow_manager_instance

    async def execute(self):
        raise NotImplementedError("Subclasses must implement the execute method.")


class TemplatePhase(Phase):
    async def execute(self):
        tasks = []
        for target_cidr in self.workflow_manager_instance.workflow_targets:  # More descriptive
            tasks.append(
                self.workflow_manager_instance.scan_manager_instance.run_discovery(target_cidr)
            )

        discovery_results = await asyncio.gather(*tasks)

        for result in discovery_results:
            for ip_address, details in result.items():
                if details.get("state") == "up":  # Using `state` to identify live hosts
                    host_manager_instance = HostManager(ip_address=ip_address)
                    host_manager_instance.update_metadata("discovered", True)
                    self.workflow_manager_instance.workflow_hosts[ip_address] = host_manager_instance


class TemplatePhase2(Phase):
    async def execute(self):
        tasks = []
        for host_instance in self.workflow_manager_instance.workflow_hosts.values():
            nse_scripts = ",".join(
                self.workflow_manager_instance.nse_configuration["categories"]["vuln"]["scripts"]
            )
            additional_arguments = f"--script {nse_scripts}"
            scan_id = await self.workflow_manager_instance.scan_manager_instance.start_scan(
                host_instance.ip_address, scan_type="vulnerability", additional_args=additional_arguments
            )
            tasks.append((host_instance, scan_id))

        for host_instance, scan_id in tasks:
            result = await self.workflow_manager_instance.scan_manager_instance.get_scan_results(scan_id)
            host_instance.update_from_scan("vulnerability", result)


class WorkflowManager:
    def __init__(self, scan_manager_instance: ScanManager, results_dir, workflow_targets: list):
        """
        Initialize WorkflowManager with all components needed to manage phases.
        ie; config triggers, and create new tool phases based on triggers.

        Args:
            scan_manager_instance (ScanManager): Manages scanning-related operations.
            workflow_targets (list): List of CIDR ranges or IP addresses to target.
        """
        self.scan_manager_instance = scan_manager_instance
        self.workflow_targets = workflow_targets
        self.workflow_hosts = {}
        self.results_dir = results_dir
        self.workflow_phases = [
            TemplatePhase("Template Enumeration", self),
            TemplatePhase2("Template Tool Usage", self),
        ]
        self.nse_configuration = self.load_nse_configuration()  # Avoids shadowing `nse_config`

    @staticmethod
    def load_nse_configuration():
        """
        Load the NSE configuration from a JSON file.

        Returns:
            dict: Parsed NSE configuration.
        """
        if not os.path.exists(NSE_CONFIG_PATH):
            raise FileNotFoundError(f"NSE config file not found at {NSE_CONFIG_PATH}")
        with open(NSE_CONFIG_PATH, "r") as file:
            return json.load(file)

    async def execute_workflow(self):
        """
        Execute all workflow phases sequentially.
        """
        for phase in self.workflow_phases:
            print(f"Executing phase: {phase.phase_name}")
            await phase.execute()