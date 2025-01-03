import logging
import os

def create_logger(name, log_file, level=logging.INFO):
    """
    Creates and configures a logger for the application.

    Args:
        name (str): Name of the logger.
        log_file (str): Path to the log file.
        level (int): Logging level (default: logging.INFO).

    Returns:
        logging.Logger: Configured logger instance.
    """
    # Ensure the directory for the log file exists
    log_dir = os.path.dirname(log_file)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Create and configure the logger
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Create a file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(level)

    # Create a console handler for debugging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    # Define a standard log format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger