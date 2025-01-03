class Host:
    def __init__(self, ip, state="unknown"):
        """
        Represents a host with minimal information.

        Args:
            ip (str): IP address of the host.
            state (str, optional): State of the host (default is "unknown").
        """
        self.ip = ip
        self.state = state
        self.scans_completed = []  # Tracks completed scans (e.g., 'discovery', 'service_scan')
        self.scan_results = {}  # Stores results of scans (e.g., {'service_scan': {...}})

    def add_scan_result(self, scan_type, result):
        """
        Add a scan result to the host.

        Args:
            scan_type (str): The type of scan (e.g., 'service_scan').
            result (dict): The result of the scan.
        """
        self.scans_completed.append(scan_type)
        self.scan_results[scan_type] = result

    def __repr__(self):
        return f"<Host ip={self.ip}, state={self.state}, scans_completed={self.scans_completed}>"
