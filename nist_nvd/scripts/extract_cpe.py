# pulls out the CPE data, walks a given directory looking for JSON files

from pathlib import Path
from typing import Optional
import click
from loguru import logger

import nist_nvd

BASE_DIR = "./data/vulnerabilities"


@click.command()
@click.argument("directory", type=click.Path(exists=True), default=BASE_DIR)
@click.option("--filename")
def extract_cpe(directory: str, filename: Optional[str] = None) -> None:
    if not Path(directory).exists():
        print(f"Directory {directory} does not exist")
        return
    else:
        logger.info("Starting to extract CPE data from {}", directory)

    for file in Path(directory).rglob("*.json"):
        if filename is not None:
            if filename not in file.name:
                continue
        logger.debug("Processing file {}", file)
        filecontents = file.read_text()
        data = nist_nvd.NVDVulnerabilityData.model_validate_json(filecontents)
        if filename is not None:
            logger.info(
                data.model_dump_json(
                    by_alias=True, exclude_unset=True, exclude_defaults=True
                )
            )


if __name__ == "__main__":
    extract_cpe()
