import os
import shutil
from pathlib import Path

from src.utils.models.ids_base import IDSBase

from ..utils.general_utilities import LOGGER, execute_command_async
from .maltrail_parser import MaltrailParser


class Maltrail(IDSBase):
    parser = None
    log_location = "/opt/logs"
    configuration_location = "/tmp/configuration/maltrail.conf"
    default_configuration_location = "/opt/maltrail/maltrail.conf"
    custom_trails_directory = "/tmp/custom-trails"
    custom_trails_file_name = "custom_trails.txt"
    sensor_path = "/opt/maltrail/sensor.py"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.log_location = os.getenv("MALTRAIL_LOG_DIRECTORY", self.log_location)
        self.configuration_location = os.getenv(
            "MALTRAIL_CONFIGURATION_LOCATION", self.configuration_location
        )
        self.default_configuration_location = os.getenv(
            "MALTRAIL_DEFAULT_CONFIG_LOCATION", self.default_configuration_location
        )
        self.custom_trails_directory = os.getenv(
            "MALTRAIL_CUSTOM_TRAILS_DIR", self.custom_trails_directory
        )
        self.sensor_path = os.getenv("MALTRAIL_SENSOR_PATH", self.sensor_path)
        self.parser = MaltrailParser(self.log_location)

    async def configure(self, file_path):
        config_directory = self.get_configuration_directory()
        os.makedirs(self.log_location, exist_ok=True)
        os.makedirs(config_directory, exist_ok=True)

        with open(file_path, "r", encoding="utf-8") as config_file:
            configuration = config_file.read()

        configuration = self.apply_runtime_overrides(configuration)

        with open(self.configuration_location, "w", encoding="utf-8") as config_file:
            config_file.write(configuration)

        LOGGER.info("Configured Maltrail using uploaded configuration")
        return "successfully configured"

    async def configure_ruleset(self, file_path):
        os.makedirs(self.custom_trails_directory, exist_ok=True)
        custom_trails_file = os.path.join(
            self.custom_trails_directory, self.custom_trails_file_name
        )
        shutil.move(file_path, custom_trails_file)

        if os.path.isfile(self.configuration_location):
            with open(self.configuration_location, "r", encoding="utf-8") as config_file:
                configuration = config_file.read()

            configuration = self.upsert_config_value(
                configuration, "CUSTOM_TRAILS_DIR", self.custom_trails_directory
            )

            with open(self.configuration_location, "w", encoding="utf-8") as config_file:
                config_file.write(configuration)

        LOGGER.info("Configured Maltrail custom trails directory")
        return "successfully configured custom trails"

    async def execute_network_analysis_command(self):
        self.write_runtime_configuration(self.tap_interface_name or "any")
        command = ["python3", self.sensor_path, "-c", self.configuration_location]
        return await execute_command_async(command)

    async def execute_static_analysis_command(self, file_path):
        self.write_runtime_configuration("any")
        command = [
            "python3",
            self.sensor_path,
            "-c",
            self.configuration_location,
            "-r",
            file_path,
        ]
        return await execute_command_async(command)

    def get_configuration_directory(self):
        return str(Path(self.configuration_location).parent)

    def write_runtime_configuration(self, monitor_interface):
        source_path = (
            self.configuration_location
            if os.path.isfile(self.configuration_location)
            else self.default_configuration_location
        )
        with open(source_path, "r", encoding="utf-8") as config_file:
            configuration = config_file.read()

        configuration = self.apply_runtime_overrides(
            configuration, monitor_interface=monitor_interface
        )

        os.makedirs(self.get_configuration_directory(), exist_ok=True)
        with open(self.configuration_location, "w", encoding="utf-8") as config_file:
            config_file.write(configuration)

    def apply_runtime_overrides(self, configuration, monitor_interface="any"):
        overrides = {
            "LOG_DIR": self.log_location,
            "MONITOR_INTERFACE": monitor_interface,
            "DISABLE_LOCAL_LOG_STORAGE": "false",
        }

        if os.path.isdir(self.custom_trails_directory):
            overrides["CUSTOM_TRAILS_DIR"] = self.custom_trails_directory

        for option, value in overrides.items():
            configuration = self.upsert_config_value(configuration, option, value)

        return configuration

    def upsert_config_value(self, configuration, option, value):
        lines = configuration.splitlines()
        updated = False

        for index, line in enumerate(lines):
            stripped = line.strip()
            if not stripped:
                continue

            if stripped == option or stripped.startswith(f"{option} "):
                lines[index] = f"{option} {value}".rstrip()
                updated = True
                break

            if stripped.startswith(f"#{option} ") or stripped == f"#{option}":
                lines[index] = f"{option} {value}".rstrip()
                updated = True
                break

        if not updated:
            lines.append(f"{option} {value}".rstrip())

        return "\n".join(lines) + "\n"
