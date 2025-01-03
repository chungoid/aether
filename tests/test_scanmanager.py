import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from core.scanmanager import ScanManager


@pytest.fixture
def scan_manager():
    return ScanManager()


# Test starting an excessive number of scans concurrently
@pytest.mark.asyncio
async def test_excessive_concurrent_scans(scan_manager):
    max_scans = 1000  # Arbitrary large number for testing limits
    tasks = [
        scan_manager.start_scan(target=f"192.168.0.{i}", scan_type="discovery")
        for i in range(1, max_scans + 1)
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Ensure all scans either succeed or fail gracefully
    assert all(
        isinstance(res, Exception) or res in scan_manager.active_scans for res in results
    ), "Not all scans were handled correctly."


# Test scan configuration file with malformed but valid JSON
def test_scan_config_malformed_json(monkeypatch):
    def mock_open(*args, **kwargs):
        from io import StringIO
        # Simulate malformed but valid JSON structure
        return StringIO('{"discovery": { "args": "-sn" "description": "missing comma"}}')

    with monkeypatch.context() as m:
        m.setattr("builtins.open", mock_open)
        with pytest.raises(ValueError, match="Failed to parse scan configuration file"):
            ScanManager()


# Test starting a scan with extremely large target ranges
@pytest.mark.asyncio
async def test_large_target_range(scan_manager):
    large_target = "192.168.0.0/16"  # Large CIDR range
    with pytest.raises(Exception, match="Expected failure for large range"):
        await scan_manager.start_scan(target=large_target, scan_type="discovery")


# Test progress updates with invalid scan IDs
def test_invalid_scan_id_progress_update(scan_manager):
    invalid_scan_id = "nonexistent_scan"
    progress_data = {"status": "invalid scan"}

    # This should not raise an exception but should log an error
    try:
        scan_manager.update_progress(invalid_scan_id, progress_data)
    except Exception as e:
        pytest.fail(f"Unexpected exception: {e}")


# Test error logging with special characters in the message
def test_error_logging_special_characters(scan_manager):
    special_characters_message = "Error: \n\t!@#$%^&*()_+{}:\"<>?[];'\\,./`~"
    scan_manager.log_error("special_scan", special_characters_message)

    assert len(scan_manager.errors) == 1, "Error was not logged."
    assert scan_manager.errors[0]["message"] == special_characters_message, "Special characters were not logged correctly."


# Test excessive scan results retrieval attempts
def test_excessive_scan_results_retrieval(scan_manager):
    for i in range(1000):  # Arbitrary large number
        scan_manager.scan_results[f"scan_{i}"] = {"result": "success"}

    for i in range(1000):
        result = scan_manager.get_scan_results(f"scan_{i}")
        assert result == {"result": "success"}, f"Result mismatch for scan_{i}"


# Test invalid scan configuration keys
def test_invalid_scan_config_keys(monkeypatch):
    def mock_open(*args, **kwargs):
        from io import StringIO
        # Valid JSON but invalid keys
        return StringIO('{"invalid_key": { "args": "-sn", "description": "Invalid key"}}')

    with monkeypatch.context() as m:
        m.setattr("builtins.open", mock_open)
        with pytest.raises(KeyError, match="discovery"):
            ScanManager()
