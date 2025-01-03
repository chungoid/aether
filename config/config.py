import os

# Base directory of the project
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Default DIRECTORY Paths
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DISCOVERY_DIR = os.path.join(RESULTS_DIR, "discovery")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# Default scan_config.json file location
SCAN_CONFIG_PATH = os.path.join(BASE_DIR, "config", "scan_config.json")


