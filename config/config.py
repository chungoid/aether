import os

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Default Results Directory
RESULTS_DIR = os.path.join(BASE_DIR, "results")

# Default scan_config file location
SCAN_CONFIG_FILE = os.path.join(BASE_DIR, "config", "scan_config.yaml")


