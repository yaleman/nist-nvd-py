from datetime import datetime
from nist_nvd.validator import validate_iso_format


def test_validate_iso_format() -> None:
    assert validate_iso_format("2021-01-01", start=True) == datetime(2021, 1, 1, 0, 0)
    assert validate_iso_format("2021-01-01", start=False) == datetime(
        2021, 1, 1, 23, 59, 59
    )
    assert validate_iso_format("2021-01-01T00:00:00Z", start=True) == datetime(
        2021, 1, 1, 0, 0, 0
    )
    assert validate_iso_format("2021-01-01T00:00:00Z", start=False) == datetime(
        2021, 1, 1, 0, 0, 0
    )
    assert validate_iso_format("2021-01-01T23:59:59Z", start=True) == datetime(
        2021, 1, 1, 23, 59, 59
    )
    assert validate_iso_format("2021-01-01T23:59:59Z", start=False) == datetime(
        2021, 1, 1, 23, 59, 59
    )
    assert validate_iso_format("2021-01-01T00:00:00", start=True) is None
    assert validate_iso_format("2021-01-01T00:00:00", start=False) is None
    assert validate_iso_format("2021-01-01T23:59:59", start=True) is None
    assert validate_iso_format("2021-01-01T23:59:59", start=False) is None
    assert validate_iso_format("2021-01-01T00:00:00ZT", start=True) is None
    assert validate_iso_format("2021-01-01T00:00:00ZT", start=False) is None
    assert validate_iso_format("2021-01-01T23:59:59ZT", start=True) is None
    assert validate_iso_format("2021-01-01T23:59:59ZT", start=False) is None
    assert validate_iso_format("2021-01-01T00:00:00ZT00:00:00Z", start=True) is None
    assert validate_iso_format("2021-01-01T00:00:00ZT00:00:00Z", start=False) is None
