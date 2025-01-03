class HostManager:
    def __init__(self, ip_address, hostname=None, os_info=None, metadata=None):
        self.ip_address = ip_address
        self.hostname = hostname
        self.open_ports = {}  # {port: service}
        self.os_info = os_info
        self.metadata = metadata or {}

    def add_open_port(self, port, service):
        """Adds a port and its associated service."""
        self.open_ports[port] = service

    def update_os_info(self, os_info):
        """Updates the operating system details."""
        self.os_info = os_info

    def merge_data(self, new_data):
        """
        Merges new scan data into the host.
        new_data should be a dictionary with keys: open_ports, os_info, etc.
        """
        for port, service in new_data.get("open_ports", {}).items():
            self.add_open_port(port, service)
        if "os_info" in new_data:
            self.update_os_info(new_data["os_info"])
        self.metadata.update(new_data.get("metadata", {}))

    def has_port(self, port):
        """Checks if a specific port is open."""
        return port in self.open_ports

    def is_vulnerable(self, criteria):
        """
        Checks if the host matches any vulnerability criteria.
        `criteria` should be a callable or a list of conditions.
        """
        for condition in criteria:
            if condition(self):
                return True
        return False

    def to_dict(self):
        """Exports the host’s data as a dictionary."""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "open_ports": self.open_ports,
            "os_info": self.os_info,
            "metadata": self.metadata,
        }