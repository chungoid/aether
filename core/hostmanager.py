from datetime import datetime, timezone
import json
from typing import Any, Dict, List


class HostManager:
    """
    Manages host-specific data and operations for a network scan workflow.
    """

    def __init__(self, ip_address: str):
        """
        Initialize a HostManager instance.

        :param ip_address: The IP address of the host.
        """
        self.ip_address = ip_address
        self.metadata = {
            "created_at": self.get_current_time(),
            "last_updated": self.get_current_time(),
        }
        self.services = {}
        self.open_ports = []
        self.scan_results = {}

    @staticmethod
    def get_current_time() -> str:
        """
        Returns the current UTC time in ISO 8601 format.

        :return: Current UTC time as a string.
        """
        return datetime.now(timezone.utc).isoformat()

    def update_metadata(self, key: str, value: Any):
        """
        Update the metadata for the host.

        :param key: Metadata key to update.
        :param value: New value for the metadata key.
        """
        self.metadata[key] = value
        self.metadata["last_updated"] = self.get_current_time()

    def add_service(self, port: int, service_name: str):
        """
        Add a service to the host.

        :param port: The port number where the service is running.
        :param service_name: The name of the service.
        """
        self.services[port] = service_name
        self.update_metadata("services_updated", True)

    def add_open_port(self, port: int):
        """
        Add an open port to the host.

        :param port: The port number to add.
        """
        if port not in self.open_ports:
            self.open_ports.append(port)
            self.update_metadata("open_ports_updated", True)

    def add_scan_result(self, scan_type: str, result: Dict[str, Any]):
        """
        Add scan results for a specific scan type.

        :param scan_type: The type of scan (e.g., "discovery", "vulnerability").
        :param result: The result data of the scan.
        """
        self.scan_results[scan_type] = result
        self.update_metadata(f"scan_{scan_type}_updated", True)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the host data to a dictionary format.

        :return: A dictionary representation of the host.
        """
        return {
            "ip_address": self.ip_address,
            "metadata": self.metadata,
            "services": self.services,
            "open_ports": self.open_ports,
            "scan_results": self.scan_results,
        }

    def save_to_file(self, file_path: str):
        """
        Save the host data to a file.

        :param file_path: Path to the file where the data will be saved.
        """
        with open(file_path, "w") as file:
            json.dump(self.to_dict(), file, indent=4)

    @staticmethod
    def merge_data(original: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Merge two dictionaries with the second one taking precedence.

        :param original: The original dictionary.
        :param updates: The dictionary with updates.
        :return: The merged dictionary.
        """
        merged = original.copy()
        merged.update(updates)
        return merged

    def update_from_scan(self, scan_type: str, scan_data: Dict[str, Any]):
        """
        Update the host data based on scan results.

        :param scan_type: The type of scan (e.g., "discovery", "port_scan").
        :param scan_data: The scan result data.
        """
        self.add_scan_result(scan_type, scan_data)
        if "ports" in scan_data:
            for port in scan_data["ports"]:
                self.add_open_port(port)
        if "services" in scan_data:
            for port, service in scan_data["services"].items():
                self.add_service(port, service)

    def execute_scan(self, scan_manager, scan_type: str):
        """
        Use ScanManager to execute a scan and update host data.

        :param scan_manager: Instance of ScanManager to execute the scan.
        :param scan_type: The type of scan to execute.
        """
        scan_result = scan_manager.run_scan(self.ip_address, scan_type)
        self.update_from_scan(scan_type, scan_result)

    def get_scan_summary(self) -> str:
        """
        Generate a summary of all scan results.

        :return: A string summary of the scan results.
        """
        summary = f"Host: {self.ip_address}\n"
        summary += f"Metadata: {self.metadata}\n"
        summary += f"Open Ports: {self.open_ports}\n"
        summary += "Services:\n"
        for port, service in self.services.items():
            summary += f"  - Port {port}: {service}\n"
        summary += "Scan Results:\n"
        for scan_type, result in self.scan_results.items():
            summary += f"  - {scan_type}: {result}\n"
        return summary