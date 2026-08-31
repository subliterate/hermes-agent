from __future__ import annotations

import runpy
import ssl
import sys
from pathlib import Path


PROXY_PATH = Path(__file__).resolve().parents[2] / "scripts" / "sandbox" / "proxy.py"


def load_proxy(tmp_path: Path, monkeypatch):
    root = tmp_path / "root"
    certs = tmp_path / "certs"
    root.mkdir()
    certs.mkdir()
    real_ca = tmp_path / "real-ca.pem"
    real_ca.write_text("unused by this unit test", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        [str(PROXY_PATH), str(root), str(certs), str(real_ca)],
    )
    return runpy.run_path(str(PROXY_PATH), run_name="sandbox_proxy_test")


class RawSocket:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def test_connect_https_retries_transient_tls_eof(tmp_path, monkeypatch):
    proxy = load_proxy(tmp_path, monkeypatch)
    monkeypatch.setattr(proxy["time"], "sleep", lambda _: None)
    attempts = []
    raw_sockets = []

    def create_connection(address, timeout):
        attempts.append((address, timeout))
        raw = RawSocket()
        raw_sockets.append(raw)
        return raw

    expected_upstream = object()

    class Context:
        def wrap_socket(self, raw, server_hostname):
            if len(attempts) < 3:
                raise ssl.SSLEOFError(8, "transient handshake EOF")
            return expected_upstream

    monkeypatch.setattr(proxy["socket"], "create_connection", create_connection)

    upstream = proxy["connect_https"]("registry.npmjs.org", 443, Context())

    assert upstream is expected_upstream
    assert len(attempts) == 3
    assert raw_sockets[0].closed is True
    assert raw_sockets[1].closed is True
    assert raw_sockets[2].closed is False


def test_connect_https_reraises_after_exhausting_retries(tmp_path, monkeypatch):
    proxy = load_proxy(tmp_path, monkeypatch)
    monkeypatch.setattr(proxy["time"], "sleep", lambda _: None)
    attempts = []
    raw_sockets = []

    def create_connection(address, timeout):
        attempts.append((address, timeout))
        raw = RawSocket()
        raw_sockets.append(raw)
        return raw

    class Context:
        def wrap_socket(self, raw, server_hostname):
            raise ConnectionResetError("upstream keeps resetting")

    monkeypatch.setattr(proxy["socket"], "create_connection", create_connection)

    try:
        proxy["connect_https"]("registry.npmjs.org", 443, Context())
    except ConnectionResetError as exc:
        assert "upstream keeps resetting" in str(exc)
    else:
        raise AssertionError("expected ConnectionResetError to propagate")

    assert len(attempts) == proxy["UPSTREAM_CONNECT_ATTEMPTS"]
    assert all(raw.closed for raw in raw_sockets)


def test_connect_https_does_not_retry_non_transient_errors(tmp_path, monkeypatch):
    proxy = load_proxy(tmp_path, monkeypatch)
    monkeypatch.setattr(proxy["time"], "sleep", lambda _: None)
    attempts = []
    raw_sockets = []

    def create_connection(address, timeout):
        attempts.append((address, timeout))
        raw = RawSocket()
        raw_sockets.append(raw)
        return raw

    class Context:
        def wrap_socket(self, raw, server_hostname):
            raise ssl.SSLCertVerificationError("certificate verify failed")

    monkeypatch.setattr(proxy["socket"], "create_connection", create_connection)

    try:
        proxy["connect_https"]("registry.npmjs.org", 443, Context())
    except ssl.SSLCertVerificationError:
        pass
    else:
        raise AssertionError("expected SSLCertVerificationError to propagate")

    assert len(attempts) == 1
    assert raw_sockets[0].closed is False
