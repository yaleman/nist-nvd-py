check:
    uv run ruff check tests nist_nvd
    uv run ruff format --check nist_nvd tests
    uv run mypy --strict tests nist_nvd
    uv run python -m pytest -s
coveralls:
    uv run coverage run -m pytest -s
    uv run coverage json -o coverage.json
    uv run coveralls
publish: check
    rm -rf ./dist/*
    uv build --force-pep517
    uv publish