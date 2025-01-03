from nmap3 import NmapAsync
from utils.logger import create_logger
from config.config import SCAN_CONFIG_PATH
import json, os

class ScanManager:

    def __init__(self, instance_id=None, path=None):
        self._created_at = self.get_current_time()
        self.instance_id = instance_id or self.generate_instance_id()
        self.logger = create_logger("scansmgr", f"logs/scansmgr_{self.instance_id}.log")
        self.scan_config = self.load_scan_config()

        self.metadata = {
            "instance_id": self.instance_id,
            "scan_config": self.scan_config,
        }

        self.nmap_async = NmapAsync(path=path)
        self.active_scans = {}
        self.scan_results = {}
        self.scan_status = {}
        self.progress = {}
        self.errors = []
        self.update_callbacks = []
        self.parser_registry = {}

    @property
    def created_at(self):
        """Returns the creation time of this ScanManager instance."""
        return self._created_at

    @staticmethod
    def get_current_time():
        """Returns the current timestamp in ISO 8601 format."""
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def generate_instance_id():
        import uuid
        return f"scan_{uuid.uuid4().hex[:8]}"

    async def start_scan(self, target, scan_type):
        """Starts an asynchronous scan using NmapAsync."""
        if scan_type not in self.scan_config:
            self.logger.error(f"Scan type '{scan_type}' not found in configuration")
            raise KeyError(f"Scan type '{scan_type}' not found in configuration")

        scan_id = self.generate_instance_id()
        try:
            self.logger.info(f"Starting scan {scan_id} for target {target} with type {scan_type}")
            self.active_scans[scan_id] = await self.nmap_async.scan_command(target, scan_type)
            self.scan_status[scan_id] = "in_progress"
            return scan_id
        except Exception as e:
            self.log_error(scan_id, str(e))
            self.scan_status[scan_id] = "errored"
            raise

    async def handle_output(self, process):
        """Handles real-time output from the subprocess."""
        async for line in process.stdout:
            self.logger.info(line.strip())
        async for line in process.stderr:
            self.logger.error(line.strip())

    def log_error(self, scan_id, error_message):
        """Logs an error for a specific scan and tracks it."""
        error_entry = {
            "scan_id": scan_id,
            "message": error_message,
            "timestamp": self.get_current_time(),
        }
        self.errors.append(error_entry)
        self.logger.error(f"Scan {scan_id} encountered an error: {error_message}")

    def update_progress(self, scan_id, progress_data):
        """Updates progress for a specific scan."""
        self.progress[scan_id] = progress_data
        self.logger.info(f"Progress for scan {scan_id}: {progress_data}")
        for callback in self.update_callbacks:
            callback(scan_id, progress_data)

    def get_scan_results(self, scan_id):
        """Retrieves results for a completed scan."""
        if scan_id not in self.scan_results:
            raise ValueError(f"No results found for scan {scan_id}")
        return self.scan_results[scan_id]

    def load_scan_config(self):
        """Loads the scan configuration settings from a predefined source."""
        if not os.path.exists(SCAN_CONFIG_PATH):
            self.logger.error(f"Configuration file not found: {SCAN_CONFIG_PATH}")
            raise FileNotFoundError(f"Configuration file not found: {SCAN_CONFIG_PATH}")

        try:
            with open(SCAN_CONFIG_PATH, "r") as config_file:
                config = json.load(config_file)

            if not isinstance(config, dict):
                raise ValueError("Invalid configuration format: Expected a JSON object.")

            self.logger.info(f"Scan configuration loaded successfully from {SCAN_CONFIG_PATH}")
            return config
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse scan configuration file <{SCAN_CONFIG_PATH}>: {e}")
            raise ValueError("Failed to parse scan configuration file.")

