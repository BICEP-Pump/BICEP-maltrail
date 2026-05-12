import os
import re
import shlex
from pathlib import Path

from src.utils.models.ids_base import Alert, IDSParser

from ..utils.general_utilities import normalize_timestamp_for_alert


class MaltrailParser(IDSParser):
    alert_file_location = "/opt/logs"
    high_priority_pattern = re.compile(
        r"(remote )?custom\)|malwaredomainlist|iot-malware|malware(?! (distribution|site))|adversary|ransomware",
        re.IGNORECASE,
    )
    medium_priority_pattern = re.compile(
        r"potential malware site|malware distribution", re.IGNORECASE
    )
    low_priority_pattern = re.compile(
        r"mass scanner|reputation|attacker|spammer|compromised|crawler|scanning",
        re.IGNORECASE,
    )
    event_log_pattern = re.compile(r"^\d{4}-\d{2}-\d{2}\.log$")

    def __init__(self, log_directory=None):
        if log_directory:
            self.alert_file_location = log_directory

    async def parse_alerts(self):
        parsed_lines = set()
        if not os.path.isdir(self.alert_file_location):
            return []

        event_logs = self.get_event_logs()
        for log_file in event_logs:
            with open(log_file, "r", encoding="utf-8") as file:
                for line in file:
                    parsed_alert = await self.parse_line(line)
                    if parsed_alert:
                        parsed_lines.add(parsed_alert)

            open(log_file, "w", encoding="utf-8").close()

        return list(parsed_lines)

    async def parse_line(self, line):
        stripped_line = line.strip()
        if not stripped_line:
            return None

        try:
            parts = shlex.split(stripped_line)
        except ValueError:
            return None

        if len(parts) < 12:
            return None

        timestamp = await normalize_timestamp_for_alert(f"{parts[0]} {parts[1]}")
        source_ip = self.normalize_value(parts[3])
        source_port = self.normalize_value(parts[4])
        destination_ip = self.normalize_value(parts[5])
        destination_port = self.normalize_value(parts[6])
        trail_type = self.normalize_value(parts[8])
        trail = self.normalize_value(parts[9])
        info = self.normalize_value(parts[10])
        reference = self.normalize_value(" ".join(parts[11:]))

        if not timestamp or not source_ip or not destination_ip or not trail_type or not trail:
            return None

        return Alert(
            time=timestamp,
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            severity=await self.normalize_threat_levels(info),
            type=trail_type,
            message=self.format_message(trail, info, reference),
        )

    async def normalize_threat_levels(self, threat):
        if not threat:
            return 0.75

        if self.high_priority_pattern.search(threat):
            return 1.0
        if self.medium_priority_pattern.search(threat):
            return 0.75
        if self.low_priority_pattern.search(threat):
            return 0.5
        return 0.75

    def get_event_logs(self):
        log_directory = Path(self.alert_file_location)
        return sorted(
            file_path
            for file_path in log_directory.iterdir()
            if file_path.is_file() and self.event_log_pattern.match(file_path.name)
        )

    def normalize_value(self, value):
        normalized_value = str(value).strip()
        if normalized_value in {"", "-"}:
            return None
        return normalized_value

    def format_message(self, trail, info, reference):
        message = trail
        if info:
            message = f"{message} - {info}"
        if reference:
            message = f"{message} ({reference})"
        return message
