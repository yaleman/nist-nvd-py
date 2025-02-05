#!python

import asyncio
from datetime import datetime

from pathlib import Path
import sys
from typing import Optional
import click
import logging

from nist_nvd import NVD
from nist_nvd.validator import validate_iso_format


def get_filename(start_index: int, results_per_page: int) -> str:
    """Get the filename for the given start index and results per page"""
    return f"vulnerabilities_{start_index}-{start_index + results_per_page}.json"


async def async_main(
    cve_id: Optional[str],
    all: bool,
    start_index: int,
    results_per_page: int,
    max_loops: Optional[int],
    logger: logging.Logger,
    pub_start_date: Optional[datetime],
    pub_end_date: Optional[datetime],
) -> int:
    """main loop of the thing.."""
    nvd = NVD()
    if cve_id is not None:
        logger.info(f"Searching for CVE with ID: {cve_id}")

        res = await nvd.get_vulnerabilities(
            cve_id=cve_id,
            start_index=0,
            results_per_page=1,
            pub_start_date=pub_start_date,
            pub_end_date=pub_end_date,
        )
        for vulnerability in res.vulnerabilities:
            vuln_filename = Path(
                "data/vulnerabilities/{}.json".format(vulnerability.cve.id)
            )
            if vuln_filename.exists():
                logger.warning(f"File {vuln_filename} already exists, skipping")
                continue
            else:
                vulnerability.cve.write_file(vuln_filename)
                logger.debug(f"Wrote {vuln_filename}")
        logger.debug("Done!")
    elif all:
        possible_max_loops = (
            f", with a maximum of {max_loops} iterations"
            if max_loops is not None
            else ""
        )
        if pub_start_date is not None and pub_end_date is not None:
            date_string = f" between {pub_start_date} and {pub_end_date}"
        else:
            date_string = ""
        logger.info(
            f"Downloading all CVEs, starting at record {start_index}, {results_per_page} at a time{possible_max_loops}.{date_string}"
        )
        res = await nvd.get_vulnerabilities(
            start_index=start_index,
            results_per_page=results_per_page,
            pub_start_date=pub_start_date,
            pub_end_date=pub_end_date,
        )
        loops = 1

        while res:
            # write out the results, doing this for the "previous" run, which includes the initial run
            for vulnerability in res.vulnerabilities:
                vuln_filename = Path(
                    "data/vulnerabilities/{}.json".format(vulnerability.cve.id)
                )
                # if vuln_filename.exists():
                # logger.debug(f"File {vuln_filename} already exists")
                # continue
                # else:
                vulnerability.cve.write_file(vuln_filename)
                logger.debug(f"Wrote {vuln_filename}")

            if max_loops is not None and loops >= int(max_loops):
                break

            start_index += results_per_page

            res = await nvd.get_vulnerabilities(
                start_index=start_index, results_per_page=results_per_page
            )
            start_index += results_per_page
            loops += 1
            if len(res.vulnerabilities) == 0:
                logger.info("No more vulnerabilities to download.")
                break
    else:
        logger.error("No CVE ID or --all flag provided. Exiting.")
        await nvd.client.close()
        return 1

    await nvd.client.close()

    return 0


@click.command()
@click.option("--cve-id", help="CVE ID to search for")
@click.option("--all", help="Download and parse all the CVE IDs", is_flag=True)
@click.option("-s", "--start-index", help="Start at this offset", default=0)
@click.option("-r", "--results-per-page", default=1000, help="Results per page")
@click.option("-d", "--debug", is_flag=True, help="Enable debug logging")
@click.option("--pub-start-date", help="Start date for published CVE")
@click.option("--pub-end-date", help="Start date for published CVE")
@click.option(
    "--max-loops", default=None, help="If you're pulling all, how many iterations"
)
def main(
    cve_id: Optional[str] = None,
    all: bool = False,
    start_index: int = 0,
    results_per_page: int = 1000,
    max_loops: Optional[int] = None,
    debug: bool = False,
    pub_start_date: Optional[str] = None,
    pub_end_date: Optional[str] = None,
) -> None:
    """Download CVE data"""

    if cve_id is None and not all:
        click.echo("No CVE ID or --all flag provided. Exiting.")
        sys.exit(1)

    logging.basicConfig(level="INFO", format="%(message)s")
    logger = logging.getLogger(name=__file__.split("/")[-2])
    logger.setLevel(logging.DEBUG if debug else logging.INFO)

    if pub_start_date is not None:
        pub_start_date_checked = validate_iso_format(pub_start_date, start=True)
        if pub_start_date_checked is None:
            logger.error(
                "Start date is not in ISO format, please ensure it matches YYYY-MM-DDTHH:MM:SSZ"
            )
            sys.exit(1)
        if pub_end_date is not None:
            pub_end_date_checked = validate_iso_format(pub_end_date, start=False)
            if pub_end_date_checked is None:
                logger.error(
                    "End date is not in ISO format, please ensure it matches YYYY-MM-DDTHH:MM:SSZ"
                )
                sys.exit(1)
        else:
            logger.error("End date is required if start date is provided")
    elif pub_end_date is not None:
        logger.error("Start date is required if end date is provided")
        sys.exit(1)

    loop = asyncio.new_event_loop()
    res = loop.run_until_complete(
        async_main(
            cve_id=cve_id,
            all=all,
            start_index=start_index,
            results_per_page=results_per_page,
            max_loops=max_loops,
            logger=logger,
            pub_start_date=pub_start_date_checked,
            pub_end_date=pub_end_date_checked,
        )
    )
    sys.exit(res)


if __name__ == "__main__":
    main()
