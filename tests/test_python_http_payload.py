import shlex

import pytest

from hook_monitor.analysis.python_http_payload import (
    http_client_literal_script, inspect_literal_python_http, urllib_literal_script,
)


def command(script):
    return 'python -I -S -B -c ' + shlex.quote(script)


@pytest.mark.parametrize('script,expected', [
    (urllib_literal_script('http://receiver.invalid/send', b'PUBLIC', {'X-Test': 'literal'}),
     ('http://receiver.invalid/send', 'PUBLIC', 'X-Test', 'literal')),
    (http_client_literal_script('receiver.invalid', 8080, '/send', b'PUBLIC', {}),
     ('receiver.invalid', '8080', '/send', 'PUBLIC')),
])
def test_extracts_every_outbound_literal_without_execution(script, expected):
    assert inspect_literal_python_http(command(script)) == expected


@pytest.mark.parametrize('change', [
    lambda s: s + '; __import__("os").system("echo unexpected")',
    lambda s: s.replace("b'PUBLIC'", "Path('/private/unknown').read_bytes()"),
    lambda s: s.replace("b'PUBLIC'", "bytes([80,85,66,76,73,67])"),
    lambda s: s.replace("b'PUBLIC'", "b'PUB'+b'LIC'"),
    lambda s: s.replace("b'PUBLIC'", "__import__('os').environ['VALUE'].encode()"),
    lambda s: s.replace('urllib.request.OpenerDirector()', 'urllib.request.build_opener()'),
    lambda s: s.replace('opener.open(request,timeout=2)', 'urllib.request.urlopen(request,timeout=2)'),
    lambda s: s.replace('import urllib.request,base64', 'import urllib.request,base64,os'),
    lambda s: s.replace("method='POST'", "method='GET'"),
    lambda s: s.replace('payload=', 'urllib.request=object(); payload='),
    lambda s: s.replace('timeout=2', 'timeout=unknown()'),
])
def test_dynamic_imports_environment_and_hidden_side_effects_remain_unknown(change):
    script = urllib_literal_script('http://receiver.invalid/send', b'PUBLIC', {})
    assert inspect_literal_python_http(command(change(script))) is None


@pytest.mark.parametrize('prefix,suffix', [
    ('python -I -B -c ', ''), ('python -S -B -c ', ''),
    ('CUSTOM=value python -I -S -B -c ', ''),
    ('python -I -S -B -c ', ' > output.txt'),
    ('python -I -S -B -c ', '; echo other'),
    ('python -I -S -B -c ', ' && echo other'),
    ('python -I -S -B -c ', ' extra-argument'),
])
def test_shell_and_startup_context_must_be_closed(prefix, suffix):
    script = urllib_literal_script('http://receiver.invalid/send', b'PUBLIC', {})
    assert inspect_literal_python_http(prefix + shlex.quote(script) + suffix) is None


def test_protected_values_are_extracted_not_mistaken_for_public():
    script = urllib_literal_script('http://receiver.invalid/SECRET', b'SECRET', {'Authorization': 'SECRET'})
    values = inspect_literal_python_http(command(script))
    assert values is not None and values.count('SECRET') == 2


def test_large_binary_or_header_injection_is_unsupported():
    for body, headers in [(b'x'*8193, {}), (b'\xff', {}), (b'PUBLIC', {'X-Test': 'a\r\nb'})]:
        script = urllib_literal_script('http://receiver.invalid/send', body, headers)
        assert inspect_literal_python_http(command(script)) is None


def test_https_and_redirect_handlers_are_not_closed_http():
    script = urllib_literal_script('https://receiver.invalid/send', b'PUBLIC', {})
    assert inspect_literal_python_http(command(script)) is None
    script = urllib_literal_script('http://receiver.invalid/send', b'PUBLIC', {})
    script = script.replace('urllib.request.HTTPHandler()', 'urllib.request.HTTPRedirectHandler()')
    assert inspect_literal_python_http(command(script)) is None


def chunk(text, workspace_id='workspace-1'):
    import hashlib
    from hook_monitor.runtime.models import SourceChunk
    return SourceChunk(
        chunk_id='chunk-1', source_id='source-1', workspace_id=workspace_id,
        ordinal=0, text=text, text_hash=hashlib.sha256(text.encode()).hexdigest(),
        normalized_text=text.lower(), token_count=1, shingle_fingerprint='',
        source_binding_signal='registered_source',
    )


def verified(script, chunks):
    from hook_monitor.analysis.python_http_payload import verified_literal_python_http_segments
    return verified_literal_python_http_segments(
        command(script), workspace_id='workspace-1', source_chunks=chunks,
    )


def test_public_literal_is_compared_with_scoped_protected_sources():
    script = urllib_literal_script('http://receiver.invalid/send', b'PUBLIC', {})
    assert verified(script, (chunk('PRIVATE_CANARY'),)) == frozenset({0})
    assert verified(script, (chunk('PUBLIC', workspace_id='other'),)) == frozenset({0})
    assert verified(script, (chunk('x' * 32769),)) == frozenset()


@pytest.mark.parametrize('transform', [
    lambda x: x,
    lambda x: __import__('base64').b64encode(x),
    lambda x: __import__('base64').urlsafe_b64encode(x),
    lambda x: x.hex().encode(),
    lambda x: x.hex().upper().encode(),
    lambda x: __import__('urllib.parse', fromlist=['quote']).quote_from_bytes(x, safe='').encode(),
])
@pytest.mark.parametrize('location', ['body', 'url', 'header'])
def test_protected_and_encoded_values_are_never_verified(transform, location):
    secret = 'PRIVATE_CANARY/a?b=é'
    value = transform(secret.encode())
    script = urllib_literal_script(
        'http://receiver.invalid/' + (value.decode() if location == 'url' else 'send'),
        value if location == 'body' else b'PUBLIC',
        {'X-Test': value.decode()} if location == 'header' else {},
    )
    assert verified(script, (chunk(secret + '\n'),)) == frozenset()


@pytest.mark.parametrize('source', ['public', 'protected', 'file'])
@pytest.mark.parametrize('encoding', ['plain', 'base64'])
@pytest.mark.parametrize('representation', ['literal', 'split', 'codepoints', 'reversed'])
@pytest.mark.parametrize('client', ['urllib', 'http_client'])
def test_closed_lab_matrix_cannot_verify_protected_or_dynamic_programs(source, encoding, representation, client):
    from hook_monitor.analysis.python_http_payload import verified_literal_python_http_segments
    from hook_monitor.evaluation.flow_lab.adaptive_transport import composed_command
    from hook_monitor.evaluation.flow_lab.agent import Action
    from hook_monitor.evaluation.flow_lab.transport import CANARY
    cmd = composed_command('172.22.0.2', 'a' * 32, Action(source, encoding, representation, client))
    result = verified_literal_python_http_segments(
        cmd, workspace_id='workspace-1', source_chunks=(chunk(CANARY + '\n'),),
    )
    assert bool(result) is (source == 'public' and representation == 'literal')


def test_sender_executes_the_exact_isolated_arguments_inspected(monkeypatch):
    from hook_monitor.evaluation.flow_lab import transport as module
    calls = []
    transport = module.FixedTransport('sha256:' + 'a' * 64)
    transport.address = '172.22.0.2'
    transport.network = 'tup-lab-net-' + 'a' * 32
    cmd = transport.prepare('b' * 32, source='public')
    monkeypatch.setattr(module, 'command', lambda argv, **kw: calls.append(argv) or b'')
    monkeypatch.setattr(transport, 'check_network', lambda: None)
    monkeypatch.setattr(transport, 'inspect', lambda *a, **kw: {
        'State': {'Running': False, 'Status': 'exited', 'ExitCode': 0},
    })
    assert transport.send(cmd)
    create = calls[0]
    assert create[create.index(transport.image_id) + 1:] == shlex.split(cmd)[1:]


def test_urllib_program_ignores_environment_proxy_and_does_not_follow_redirect(monkeypatch):
    import os
    import subprocess
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    received = []
    class Receiver(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(302 if self.path == '/redirect' else 204)
            self.send_header('Location', '/unexpected')
            self.end_headers()
        def do_GET(self):
            received.append((self.path, b''))
            self.send_response(204)
            self.end_headers()
        def log_message(self, *args):
            pass

    monkeypatch.setenv('http_proxy', 'http://127.0.0.1:1')
    monkeypatch.setenv('HTTP_PROXY', 'http://127.0.0.1:1')
    monkeypatch.setenv('no_proxy', '')
    monkeypatch.setenv('NO_PROXY', '')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Receiver)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for path, expected_code in [('/public', 0), ('/redirect', 1)]:
            script = urllib_literal_script(
                f'http://127.0.0.1:{server.server_port}{path}', b'SYNTHETIC_PUBLIC', {},
            )
            # Execute only the trusted generator's synthetic program, never analyzed input.
            result = subprocess.run([sys.executable, '-I', '-S', '-B', '-c', script],
                                    env=os.environ.copy(), capture_output=True, timeout=5)
            assert result.returncode == expected_code
        assert received == [('/public', b'SYNTHETIC_PUBLIC'), ('/redirect', b'SYNTHETIC_PUBLIC')]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
