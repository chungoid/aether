import asyncio
import json
from typing import Dict, List, Any
from core.scanmanager import ScanManager
from core.hostmanager import HostManager
from random import choice

class WorkflowManager:
    def __init__(self):
        self.scan_manager = ScanManager()
        self.hosts: Dict[str, HostManager] = {}

         # Host Discovery
    async def handle_workflow(self, target_range: str):

        discovery_results = await self.run_scan("discovery", target_range)
        self.process_discovery_results(discovery_results)

        # Port Discovery
        port_scan_tasks = [self.run_scan("port_scan", host) for host in self.hosts]
        port_results = await asyncio.gather(*port_scan_tasks)
        self.process_port_results(port_results)

        # Service Identification
        service_scan_tasks = [self.run_scan("service_scan", host) for host in self.hosts]
        service_results = await asyncio.gather(*service_scan_tasks)
        self.process_service_results(service_results)

        # OS Detection
        os_scan_tasks = [self.run_scan("os_detection", host) for host in self.hosts]
        os_results = await asyncio.gather(*os_scan_tasks)
        self.process_os_results(os_results)

        # Dynamic Scripted Scans
        await self.run_dynamic_scans()

        # High Resource / Suggestion Storage
        self.save_suggestions_to_file()

    async def run_scan(self, scan_type: str, target: str) -> Dict[str, Any]:
        """
        Run a specific scan type using ScanManager.
        """
        scan_config = self.scan_manager.scan_config.get(scan_type, {})
        args = scan_config.get("args", "")
        return await self.scan_manager.run_scan(target, args)

    def process_discovery_results(self, results: Dict[str, Any]):
        """
        Process host discovery results and initialize HostManager instances.
        """
        for ip, details in results.items():
            if details.get("status") == "up":
                self.hosts[ip] = HostManager(ip)

    def process_port_results(self, results: List[Dict[str, Any]]):
        """
        Process port scan results and update HostManager instances.
        """
        for result in results:
            ip = result["host"]
            self.hosts[ip].update_from_scan("port_scan", result)

    def process_service_results(self, results: List[Dict[str, Any]]):
        """
        Process service scan results and update HostManager instances.
        """
        for result in results:
            ip = result["host"]
            self.hosts[ip].update_from_scan("service_scan", result)

    def process_os_results(self, results: List[Dict[str, Any]]):
        """
        Process OS detection results and update HostManager instances.
        """
        for result in results:
            ip = result["host"]
            self.hosts[ip].update_from_scan("os_detection", result)

    async def run_dynamic_scans(self):
        """
        Run service-specific scans dynamically based on gathered data.
        """
        for ip, host in self.hosts.items():
            for port in host.open_ports:
                service = host.services.get(port, "unknown")
                if service.startswith("http"):
                    await self.run_web_scans(ip, port)
                elif service.startswith("smb"):
                    await self.run_smb_scans(ip)
                elif service.startswith("ssh"):
                    await self.run_ssh_scans(ip)

    async def run_web_scans(self, ip: str, port: int):
        """
        Run web-specific scans.
        """
        print(f"Running web scans for {ip}:{port}...")

    async def run_smb_scans(self, ip: str):
        """
        Run SMB-specific scans.
        """
        print(f"Running SMB scans for {ip}...")

    async def run_ssh_scans(self, ip: str):
        """
        Run SSH-specific scans.
        """
        print(f"Running SSH scans for {ip}...")

    def save_suggestions_to_file(self, file_path="suggestions.json"):
        """
        Save deferred suggestions to a JSON file for user review.
        """
        suggestions = {ip: host.metadata.get("suggestions", []) for ip, host in self.hosts.items()}
        with open(file_path, "w") as file:
            json.dump(suggestions, file, indent=4)