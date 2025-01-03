import os

# Project root DIRECTORY PATH
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# default DIRECTORY PATHS
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DISCOVERY_DIR = os.path.join(RESULTS_DIR, "discovery")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

# filepaths for scans configs (default: config/scan_config.json)
SCAN_CONFIG_PATH = os.path.join(BASE_DIR, "config", "scan_config.json")
NSE_CONFIG_PATH = os.path.join(BASE_DIR, "config", "nse_config.json")




