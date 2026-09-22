from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import tarfile

from scripts.audit_public_source import _scan_content


def test_archive_matches_manifest_and_is_scanned():
    root = Path(__file__).resolve().parents[1] / 'legacy/v0.1'
    content = (root / 'tests-and-tools.tar.gz').read_bytes()
    with tarfile.open(fileobj=io.BytesIO(content), mode='r:gz') as archive:
        actual = {m.name: hashlib.sha256(archive.extractfile(m).read()).hexdigest()
                  for m in archive.getmembers()}
    assert actual == json.loads((root / 'tests-and-tools.sha256.json').read_text())
    findings, observations = Counter(), Counter()
    _scan_content(content, findings, observations, binary_allowed=False)
    assert not findings
    assert observations['audited_archive'] == 1


def test_archive_does_not_hide_forbidden_files():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:gz') as archive:
        member = tarfile.TarInfo('events.db')
        member.size = 3
        archive.addfile(member, io.BytesIO(b'abc'))
    findings = Counter()
    _scan_content(stream.getvalue(), findings, Counter(), binary_allowed=False)
    assert findings['forbidden_path'] == 1
