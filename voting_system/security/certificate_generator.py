"""Generate CA/server/client certificates for MQTT TLS using OpenSSL."""
from __future__ import annotations

import logging
import subprocess
from pathlib import Path

from config.config import CERTIFICATES_DIR

logger = logging.getLogger(__name__)


def _run(cmd: list[str], cwd: Path) -> None:
    subprocess.run(cmd, cwd=str(cwd), check=True)


def generate_certificates(certificates_dir: str | Path | None = None) -> None:
    """Generate CA, server, and client cert/key files with OpenSSL commands."""
    cert_dir = Path(certificates_dir) if certificates_dir is not None else CERTIFICATES_DIR
    cert_dir.mkdir(parents=True, exist_ok=True)

    ca_key = cert_dir / "ca.key"
    ca_crt = cert_dir / "ca.crt"
    server_key = cert_dir / "server.key"
    server_csr = cert_dir / "server.csr"
    server_crt = cert_dir / "server.crt"
    client_key = cert_dir / "client.key"
    client_csr = cert_dir / "client.csr"
    client_crt = cert_dir / "client.crt"

    if not ca_key.exists() or not ca_crt.exists():
        _run(["openssl", "genrsa", "-out", str(ca_key), "2048"], cert_dir)
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-nodes",
                "-key",
                str(ca_key),
                "-sha256",
                "-days",
                "3650",
                "-out",
                str(ca_crt),
                "-subj",
                "/CN=VotingSystem-CA",
            ],
            cert_dir,
        )

    if not server_key.exists() or not server_crt.exists():
        _run(["openssl", "genrsa", "-out", str(server_key), "2048"], cert_dir)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(server_key),
                "-out",
                str(server_csr),
                "-subj",
                "/CN=localhost",
            ],
            cert_dir,
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(server_csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(server_crt),
                "-days",
                "3650",
                "-sha256",
            ],
            cert_dir,
        )

    if not client_key.exists() or not client_crt.exists():
        _run(["openssl", "genrsa", "-out", str(client_key), "2048"], cert_dir)
        _run(
            [
                "openssl",
                "req",
                "-new",
                "-key",
                str(client_key),
                "-out",
                str(client_csr),
                "-subj",
                "/CN=voting-client",
            ],
            cert_dir,
        )
        _run(
            [
                "openssl",
                "x509",
                "-req",
                "-in",
                str(client_csr),
                "-CA",
                str(ca_crt),
                "-CAkey",
                str(ca_key),
                "-CAcreateserial",
                "-out",
                str(client_crt),
                "-days",
                "3650",
                "-sha256",
            ],
            cert_dir,
        )

    for csr in (server_csr, client_csr):
        if csr.exists():
            csr.unlink()

    logger.info("TLS certificates generated in %s", cert_dir)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    generate_certificates()
