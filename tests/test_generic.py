import os
import pytest
import tempfile

from nist_nvd import WriteFileMixin


def test_write_file_mixin() -> None:
    test = WriteFileMixin()
    with pytest.raises(NotImplementedError):
        test.model_dump_json()
    with tempfile.TemporaryDirectory(
        delete=True, ignore_cleanup_errors=True
    ) as this_temp_dir:
        with pytest.raises(NotImplementedError):
            test.write_file(os.path.join(this_temp_dir, "test.txt"))
