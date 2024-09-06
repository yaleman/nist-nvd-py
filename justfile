check:
    uv run ruff check tests nist_nvd
    uv run ruff format --check nist_nvd tests
    uv run mypy --strict tests nist_nvd
    uv run python -m pytest -s