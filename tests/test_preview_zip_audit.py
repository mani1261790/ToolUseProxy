import importlib.util
import io
from collections import Counter
from pathlib import Path
import zipfile

spec = importlib.util.spec_from_file_location("audit", Path(__file__).parents[1] / "scripts/audit_public_source.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def scan(name, content):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        z.writestr(name, content)
    findings, observations = Counter(), Counter()
    audit._scan_content(stream.getvalue(), findings, observations, binary_allowed=False)
    return findings, observations


def test_zip_source_is_audited():
    findings, observations = scan("runtime/app.py", "print('example')")
    assert not findings
    assert observations["audited_archive"] == 1


def test_zip_cannot_hide_binary_or_control_files():
    assert scan("file.dat", b"\x00")[0]["binary_blob"] == 1
    assert scan(".env", "SETTING=value")[0]["forbidden_path"] == 1


def test_zip_rejects_traversal_nested_archive_and_large_members():
    assert scan("../outside.py", "text")[0]["invalid_archive"] == 1
    assert scan("nested.zip", b"PK\x03\x04")[0]["invalid_archive"] == 1
    assert scan("large.txt", b"x" * (audit.MAX_BLOB_BYTES + 1))[0]
