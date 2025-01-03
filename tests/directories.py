import unittest
import os
from config import config


class TestDirectoryCreation(unittest.TestCase):
    def setUp(self):
        """
        Setup for the test. Ensures no leftover directories from previous tests.
        """
        # Remove directories if they exist
        if os.path.exists(config.DISCOVERY_DIR):
            os.rmdir(config.DISCOVERY_DIR)
        if os.path.exists(config.RESULTS_DIR):
            os.rmdir(config.RESULTS_DIR)

    def test_directory_creation(self):
        """
        Test to check if the required directories are created.
        """
        # Check if RESULTS_DIR is created
        self.assertTrue(os.path.exists(config.RESULTS_DIR), "Results directory not created.")

        # Check if DISCOVERY_DIR is created
        self.assertTrue(os.path.exists(config.DISCOVERY_DIR), "Discovery directory not created.")

    def tearDown(self):
        """
        Cleanup after the test. Removes created directories.
        """
        if os.path.exists(config.DISCOVERY_DIR):
            os.rmdir(config.DISCOVERY_DIR)
        if os.path.exists(config.RESULTS_DIR):
            os.rmdir(config.RESULTS_DIR)


if __name__ == "__main__":
    unittest.main()