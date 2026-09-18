import os
import shutil
from pathlib import Path

from src.utils.models.ids_base import IDSBase

from ..utils.general_utilities import LOGGER, execute_command_async
from .maltrail_parser import MaltrailParser


class Maltrail(IDSBase):
    parser = None
    log_location = "/opt/logs"
    configuration_location = "/tmp/maltrail.conf"
    default_configuration_location = "/opt/maltrail/maltrail.conf"
    custom_trails_directory = "/tmp/custom-trails"
    custom_trails_file_name = "custom_trails.txt"
    sensor_path = "maltrail-sensor"
    working_dir = "/opt/maltrail"

    async def configure(self, file_path):
        shutil.move(file_path, self.configuration_location)
        try:
            os.makedirs(self.log_location, exist_ok=True)
            LOGGER.info("Configured Maltrail using uploaded configuration")
            return "succesfully configured"
        except Exception as e:
            LOGGER.error(f"Exception occurred while configuring Maltrail: {e}")
            raise HTTPException(
                status_code=500,
                detail="Exception occured occured while configuring Maltrail. Please check the confgiuration file again and make sure it is valid!",
            )

    async def configure_ruleset(self, file_path):
        LOGGER.info("Maltrail does not require a ruleset configuration, skipping this step.")
        return "successfully configured rules"

    async def execute_network_analysis_command(self):
        os.chdir(self.working_dir)
        command = [self.sensor_path, "-c", self.configuration_location]
        return await execute_command_async(command)

    async def execute_static_analysis_command(self, file_path):
        os.chdir(self.working_dir)
        command = [
            self.sensor_path,
            "-c",
            self.configuration_location,
            "-r",
            file_path,
        ]
        return await execute_command_async(command)