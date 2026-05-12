from pathlib import Path

import pytest

from src.models.maltrail_parser import MaltrailParser
from src.utils.models.ids_base import Alert


@pytest.fixture
def parser(tmp_path):
    return MaltrailParser(str(tmp_path))


@pytest.mark.asyncio
async def test_parse_alerts_empty_directory(parser: MaltrailParser):
    alerts = await parser.parse_alerts()
    assert alerts == []


@pytest.mark.asyncio
async def test_parse_alerts_valid_and_invalid_data(parser: MaltrailParser):
    log_file = Path(parser.alert_file_location) / "2026-05-12.log"
    log_file.write_text(
        '\n'.join(
            [
                '2026-05-12 11:33:13.123456 sensor-a 192.168.10.15 63176 239.255.255.250 1900 UDP IP 239.255.255.250 "mass scanner" static',
                '2026-05-12 11:33:14.123456 sensor-a 147.32.84.165 1349 81.10.0.18 6667 TCP URL bad.example "ransomware" static',
                'invalid log line',
            ]
        )
        + '\n',
        encoding="utf-8",
    )

    alerts = await parser.parse_alerts()

    assert len(alerts) == 2
    alerts = sorted(alerts, key=lambda alert: (alert.time, alert.source_ip))
    assert alerts[0].message == "239.255.255.250 - mass scanner (static)"
    assert alerts[0].severity == 0.5
    assert alerts[1].type == "URL"
    assert alerts[1].severity == 1.0
    assert log_file.read_text(encoding="utf-8") == ""


@pytest.mark.asyncio
async def test_parse_line_valid(parser: MaltrailParser):
    line_data = '2026-05-12 11:33:13.123456 sensor-a 192.168.10.15 63176 239.255.255.250 1900 UDP IP 239.255.255.250 "mass scanner" static'
    alert = await parser.parse_line(line_data)
    assert isinstance(alert, Alert)
    assert alert.message == "239.255.255.250 - mass scanner (static)"
    assert alert.severity == 0.5


@pytest.mark.asyncio
async def test_parse_line_with_missing_ports(parser: MaltrailParser):
    line_data = '2026-05-12 11:33:13.123456 sensor-a 192.168.10.15 - 239.255.255.250 - UDP DNS suspicious.example "potential malware site" static'
    alert = await parser.parse_line(line_data)
    assert isinstance(alert, Alert)
    assert alert.source_port is None
    assert alert.destination_port is None
    assert alert.severity == 0.75


@pytest.mark.asyncio
async def test_parse_line_missing_fields(parser: MaltrailParser):
    line_data = '2026-05-12 11:33:13.123456 sensor-a 192.168.10.15 239.255.255.250'
    alert = await parser.parse_line(line_data)
    assert alert is None


@pytest.mark.asyncio
async def test_normalize_threat_levels(parser: MaltrailParser):
    assert await parser.normalize_threat_levels("ransomware") == 1.0
    assert await parser.normalize_threat_levels("potential malware site") == 0.75
    assert await parser.normalize_threat_levels("mass scanner") == 0.5
    assert await parser.normalize_threat_levels("unknown classification") == 0.75
    assert await parser.normalize_threat_levels(None) == 0.75
