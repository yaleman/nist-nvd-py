from datetime import datetime
from typing import Optional


def validate_iso_format(date_str: str, start: bool) -> Optional[datetime]:
    if len(date_str.split("T")) == 1:
        if start:
            date_str = date_str + "T00:00:00Z"
        else:
            date_str = date_str + "T23:59:59Z"
    try:
        return datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
