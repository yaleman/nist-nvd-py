import os
import sys
from typing import Any, Generator
from nist_nvd import NVD, NVDCPEs, NVDSources, NVDVulnerabilities
import pytest
from contextlib import contextmanager

from nist_nvd.config import Config


@pytest.mark.asyncio(loop_scope="function")
async def test_get() -> None:
    nvd = NVD()
    assert nvd.api_key == os.getenv("NVD_API_KEY")
    print("getting sources")
    await nvd.get_sources(results_per_page=100)
    print("getting products")
    await nvd.get_products(results_per_page=100)
    print("getting vulnerabilities starting at 9000 and getting 100 results")
    res = await nvd.get_vulnerabilities(start_index=9000, results_per_page=100)
    res.model_dump_json()


def test_nvd_sources_parser() -> None:
    file = open("tests/example.sources.json", "r").read()
    response = NVDSources.model_validate_json(file)
    assert response.results_per_page == 386

    response.model_dump_json(indent=4)


def test_nvd_products_parser() -> None:
    file = open("tests/example.products.json", "r").read()
    response = NVDCPEs.model_validate_json(file)
    assert response.results_per_page == 1000
    response.model_dump_json(indent=4)
    response.products[0].cpe.get_title("en")


def test_nvd_vulnerabilities_parser() -> None:
    for filename in os.listdir("tests"):
        if filename.startswith("example.vulnerabilities"):
            print(f"Checking {filename}")
            file = open(f"tests/{filename}").read()
            data = NVDVulnerabilities.model_validate_json(file)
            data.vulnerabilities[0].cve.get_description("en")
            data.vulnerabilities[0].cve.get_description("fr")
        else:
            print(f"Skipping {filename}", file=sys.stderr)


@contextmanager
def mocked_env_var(
    monkeypatch: Any, var_name: str, var_value: str
) -> Generator[Any, Any, Any]:
    monkeypatch.setenv(var_name, var_value)
    yield
    monkeypatch.delenv(var_name)


def test_nvd_with_config(monkeypatch: Any) -> None:
    with mocked_env_var(monkeypatch, "MY_ENV_VAR", "mocked_value"):
        assert os.environ["MY_ENV_VAR"] == "mocked_value"

    with mocked_env_var(monkeypatch, "NVD_API_KEY", "mocked_value"):
        assert os.getenv("NVD_API_KEY") == "mocked_value"

        assert Config().api_key == "mocked_value"  # type: ignore
    assert Config().api_key is None  # type: ignore
