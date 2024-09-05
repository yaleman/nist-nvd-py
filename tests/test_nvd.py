import os
from nist_nvd import NVD, NVDCPEs, NVDSources, NVDVulnerabilities
import pytest


@pytest.mark.asyncio
async def test_get() -> None:
    nvd = NVD(os.getenv("NVD_API_KEY"))
    await nvd.get_sources()
    await nvd.get_products()
    start_index = 9000
    results_per_page = 1000
    await nvd.get_vulnerabilities(
        start_index=start_index, results_per_page=results_per_page
    )

    assert nvd.api_key == os.getenv("NVD_API_KEY")


def test_nvd_sources_parser() -> None:
    file = open("tests/example.sources.json", "r").read()
    response = NVDSources.model_validate_json(file)
    assert response.results_per_page == 386

    print(response.model_dump_json(indent=4))


def test_nvd_products_parser() -> None:
    file = open("tests/example.products.json", "r").read()
    response = NVDCPEs.model_validate_json(file)
    assert response.results_per_page == 1000
    print(response.model_dump_json(indent=4))


def test_nvd_vulnerabilities_parser() -> None:
    for filename in os.listdir("tests"):
        if filename.startswith("example.vulnerabilities"):
            print(f"Checking {filename}")
            file = open(f"tests/{filename}").read()
            NVDVulnerabilities.model_validate_json(file)
        else:
            print(f"Skipping {filename}")
