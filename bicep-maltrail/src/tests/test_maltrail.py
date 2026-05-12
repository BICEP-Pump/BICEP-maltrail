from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from src.models.maltrail import Maltrail


@pytest.fixture
def ids(tmp_path):
    ids_instance = Maltrail()
    ids_instance.container_id = 123
    ids_instance.tap_interface_name = "tap123"
    ids_instance.configuration_location = str(tmp_path / "configuration" / "maltrail.conf")
    ids_instance.default_configuration_location = str(tmp_path / "default-maltrail.conf")
    ids_instance.log_location = str(tmp_path / "logs")
    ids_instance.custom_trails_directory = str(tmp_path / "custom-trails")
    ids_instance.sensor_path = "/opt/maltrail/sensor.py"
    ids_instance.parser.alert_file_location = ids_instance.log_location
    return ids_instance


@pytest.mark.asyncio
async def test_configure(ids: Maltrail, tmp_path):
    source_config = tmp_path / "uploaded.conf"
    source_config.write_text(
        "CAPTURE_BUFFER 10%\nMONITOR_INTERFACE any\nLOG_DIR /var/log/maltrail\n",
        encoding="utf-8",
    )

    response = await ids.configure(str(source_config))

    saved_config = Path(ids.configuration_location)
    assert saved_config.exists()
    content = saved_config.read_text(encoding="utf-8")
    assert f"LOG_DIR {ids.log_location}" in content
    assert "MONITOR_INTERFACE any" in content
    assert "DISABLE_LOCAL_LOG_STORAGE false" in content
    assert response == "successfully configured"


@pytest.mark.asyncio
async def test_configure_ruleset(ids: Maltrail, tmp_path):
    custom_trails = tmp_path / "custom-trails.txt"
    custom_trails.write_text("evil.example, custom trail\n", encoding="utf-8")
    Path(ids.configuration_location).parent.mkdir(parents=True, exist_ok=True)
    Path(ids.configuration_location).write_text(
        "CAPTURE_BUFFER 10%\nMONITOR_INTERFACE any\nLOG_DIR /var/log/maltrail\n",
        encoding="utf-8",
    )

    response = await ids.configure_ruleset(str(custom_trails))

    saved_trails = Path(ids.custom_trails_directory) / ids.custom_trails_file_name
    assert saved_trails.exists()
    saved_config = Path(ids.configuration_location).read_text(encoding="utf-8")
    assert f"CUSTOM_TRAILS_DIR {ids.custom_trails_directory}" in saved_config
    assert response == "successfully configured custom trails"


@pytest.mark.asyncio
@patch("src.models.maltrail.execute_command_async", new_callable=AsyncMock)
async def test_execute_network_analysis_command(mock_execute_command, ids: Maltrail, tmp_path):
    mock_execute_command.return_value = 555
    Path(ids.configuration_location).parent.mkdir(parents=True, exist_ok=True)
    Path(ids.configuration_location).write_text(
        "CAPTURE_BUFFER 10%\nMONITOR_INTERFACE any\nLOG_DIR /var/log/maltrail\n",
        encoding="utf-8",
    )

    pid = await ids.execute_network_analysis_command()

    mock_execute_command.assert_called_once_with(
        ["python3", ids.sensor_path, "-c", ids.configuration_location]
    )
    saved_config = Path(ids.configuration_location).read_text(encoding="utf-8")
    assert "MONITOR_INTERFACE tap123" in saved_config
    assert pid == 555


@pytest.mark.asyncio
@patch("src.models.maltrail.execute_command_async", new_callable=AsyncMock)
async def test_execute_static_analysis_command(mock_execute_command, ids: Maltrail, tmp_path):
    mock_execute_command.return_value = 777
    dataset_path = "/path/to/capture.pcap"
    Path(ids.configuration_location).parent.mkdir(parents=True, exist_ok=True)
    Path(ids.configuration_location).write_text(
        "CAPTURE_BUFFER 10%\nMONITOR_INTERFACE tap999\nLOG_DIR /var/log/maltrail\n",
        encoding="utf-8",
    )

    pid = await ids.execute_static_analysis_command(dataset_path)

    mock_execute_command.assert_called_once_with(
        ["python3", ids.sensor_path, "-c", ids.configuration_location, "-r", dataset_path]
    )
    saved_config = Path(ids.configuration_location).read_text(encoding="utf-8")
    assert "MONITOR_INTERFACE any" in saved_config
    assert pid == 777


def test_get_configuration_directory(ids: Maltrail):
    ids.configuration_location = "/my/config/location/maltrail.conf"
    config_dir = ids.get_configuration_directory()
    assert config_dir == "/my/config/location"
