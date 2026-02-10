"""Certificate management for Open Relay Portal.

Handles certificate info parsing, self-signed generation, Let's Encrypt
automation, custom cert upload/validation, and .env file management.
"""

import datetime
import ipaddress
import os
import re
import shutil
import subprocess
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.x509.oid import NameOID, ExtensionOID


# =============================================================================
# Certificate Information
# =============================================================================

def get_cert_info(cert_path: str) -> dict:
    """Read a PEM certificate and return structured information.

    Returns dict with: subject, issuer, sans, not_before, not_after,
    days_until_expiry, is_expired, is_self_signed, fingerprint_sha256,
    key_type, serial_number, method.
    """
    cert_data = Path(cert_path).read_bytes()
    cert = x509.load_pem_x509_certificate(cert_data)

    now = datetime.datetime.now(datetime.timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
    days_until_expiry = (not_after - now).days

    # Extract subject and issuer as dicts
    subject = _name_to_dict(cert.subject)
    issuer = _name_to_dict(cert.issuer)

    # SANs
    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Key type
    pub_key = cert.public_key()
    if isinstance(pub_key, rsa.RSAPublicKey):
        key_type = f"RSA {pub_key.key_size}"
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        key_type = f"EC {pub_key.curve.name}"
    else:
        key_type = type(pub_key).__name__

    # Fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    fingerprint_formatted = ":".join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))

    # Self-signed check
    is_self_signed = cert.subject == cert.issuer

    # Detect method
    method = detect_cert_method(cert_path)

    return {
        "subject": subject,
        "issuer": issuer,
        "sans": sans,
        "serial_number": str(cert.serial_number),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_until_expiry": days_until_expiry,
        "is_expired": days_until_expiry <= 0,
        "is_self_signed": is_self_signed,
        "fingerprint_sha256": fingerprint_formatted,
        "key_type": key_type,
        "method": method,
    }


def _name_to_dict(name: x509.Name) -> dict:
    """Convert x509.Name to a simple dict."""
    result = {}
    oid_map = {
        NameOID.COMMON_NAME: "CN",
        NameOID.ORGANIZATION_NAME: "O",
        NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        NameOID.COUNTRY_NAME: "C",
        NameOID.STATE_OR_PROVINCE_NAME: "ST",
        NameOID.LOCALITY_NAME: "L",
    }
    for attr in name:
        key = oid_map.get(attr.oid, attr.oid.dotted_string)
        result[key] = attr.value
    return result


def validate_cert_key_pair(cert_pem: bytes, key_pem: bytes) -> tuple[bool, str]:
    """Validate that a certificate and private key match.

    Returns (is_valid, error_message).
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return False, f"Invalid certificate PEM: {e}"

    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except Exception as e:
        return False, f"Invalid private key PEM: {e}"

    # Compare public keys
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if cert_pub != key_pub:
        return False, "Certificate and private key do not match"

    return True, ""


def detect_cert_method(cert_path: str) -> str:
    """Detect certificate method based on issuer.

    Returns 'letsencrypt', 'selfsigned', or 'custom'.
    """
    try:
        cert_data = Path(cert_path).read_bytes()
        cert = x509.load_pem_x509_certificate(cert_data)
        issuer = _name_to_dict(cert.issuer)
        subject = _name_to_dict(cert.subject)

        # Check for Let's Encrypt issuers
        issuer_o = issuer.get("O", "").lower()
        if "let's encrypt" in issuer_o or "letsencrypt" in issuer_o:
            return "letsencrypt"

        # Self-signed: subject == issuer
        if cert.subject == cert.issuer:
            return "selfsigned"

        # Check if cert path is in Let's Encrypt directory
        if "/letsencrypt/" in str(cert_path):
            return "letsencrypt"

        return "custom"
    except Exception:
        return "custom"


# =============================================================================
# Self-Signed Certificate Generation
# =============================================================================

def generate_self_signed_cert(
    hostname: str,
    output_dir: str,
    validity_days: int = 365,
) -> tuple[str, str]:
    """Generate a self-signed server certificate.

    Creates RSA 4096-bit key, adds SANs for hostname + localhost.
    Returns (cert_path, key_path).
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Generate private key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )

    # Build subject
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Open Relay Portal"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Self-Signed"),
    ])

    # Build SANs
    san_entries = [
        x509.DNSName(hostname),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        x509.IPAddress(ipaddress.IPv6Address("::1")),
    ]

    # If hostname looks like an IP, add it as IPAddress SAN too
    try:
        san_entries.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        pass

    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = str(output_path / "selfsigned_cert.pem")
    key_path = str(output_path / "selfsigned_key.pem")

    # Write certificate
    Path(cert_path).write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
    )
    os.chmod(cert_path, 0o644)

    # Write private key (restricted permissions)
    Path(key_path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)

    return cert_path, key_path


# =============================================================================
# Let's Encrypt
# =============================================================================

def request_letsencrypt_cert(
    hostname: str,
    email: str,
    method: str = "standalone",
) -> tuple[bool, str]:
    """Request or renew a Let's Encrypt certificate via certbot.

    Returns (success, message).
    """
    if not shutil.which("certbot"):
        return False, "certbot is not installed. Install with: apt install certbot"

    cmd = [
        "certbot", "certonly",
        "--non-interactive",
        "--agree-tos",
        "--email", email,
        "-d", hostname,
    ]

    if method == "standalone":
        cmd.extend(["--standalone", "--preferred-challenges", "http"])
    elif method == "webroot":
        cmd.extend(["--webroot", "-w", "/var/www/html"])
    else:
        return False, f"Unsupported method: {method}"

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            cert_path, key_path = get_letsencrypt_cert_paths(hostname)
            return True, f"Certificate issued. Cert: {cert_path}, Key: {key_path}"
        else:
            error = result.stderr.strip() or result.stdout.strip()
            return False, f"certbot failed: {error}"
    except subprocess.TimeoutExpired:
        return False, "certbot timed out after 120 seconds"
    except Exception as e:
        return False, f"Failed to run certbot: {e}"


def get_letsencrypt_cert_paths(hostname: str) -> tuple[str, str]:
    """Return standard Let's Encrypt certificate paths."""
    base = f"/etc/letsencrypt/live/{hostname}"
    return f"{base}/fullchain.pem", f"{base}/privkey.pem"


def install_renewal_hook(service_name: str = "portal") -> bool:
    """Install a certbot post-renewal hook to restart the portal service.

    Returns True if hook was installed successfully.
    """
    hook_dir = Path("/etc/letsencrypt/renewal-hooks/post")
    try:
        hook_dir.mkdir(parents=True, exist_ok=True)
        hook_path = hook_dir / f"{service_name}-reload.sh"
        hook_path.write_text(
            f"#!/bin/bash\n"
            f"# Reload {service_name} after certificate renewal\n"
            f"systemctl restart {service_name}.service 2>/dev/null || true\n"
        )
        hook_path.chmod(0o755)
        return True
    except Exception:
        return False


def check_letsencrypt_renewal(hostname: str) -> dict:
    """Check certbot renewal status for a hostname."""
    result = {
        "installed": bool(shutil.which("certbot")),
        "cert_exists": False,
        "auto_renew": False,
    }

    cert_path, _ = get_letsencrypt_cert_paths(hostname)
    result["cert_exists"] = Path(cert_path).exists()

    # Check if certbot timer is active
    try:
        timer_check = subprocess.run(
            ["systemctl", "is-active", "certbot.timer"],
            capture_output=True, text=True, timeout=5,
        )
        result["auto_renew"] = timer_check.stdout.strip() == "active"
    except Exception:
        pass

    return result


# =============================================================================
# Custom Certificate Upload
# =============================================================================

def save_uploaded_cert(
    cert_data: bytes,
    key_data: bytes,
    output_dir: str,
) -> tuple[str, str]:
    """Validate and save uploaded PEM certificate and key files.

    Sets proper file permissions (0o644 for cert, 0o600 for key).
    Returns (cert_path, key_path).
    Raises ValueError on invalid input.
    """
    # Validate the pair first
    is_valid, error = validate_cert_key_pair(cert_data, key_data)
    if not is_valid:
        raise ValueError(error)

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    cert_path = str(output_path / "custom_cert.pem")
    key_path = str(output_path / "custom_key.pem")

    Path(cert_path).write_bytes(cert_data)
    os.chmod(cert_path, 0o644)

    Path(key_path).write_bytes(key_data)
    os.chmod(key_path, 0o600)

    return cert_path, key_path


# =============================================================================
# .env File Management
# =============================================================================

def update_env_value(env_path: str, key: str, value: str) -> None:
    """Update or add a key=value pair in a .env file.

    If the key exists, its value is replaced. If not, it's appended.
    """
    env_file = Path(env_path)

    if env_file.exists():
        lines = env_file.read_text().splitlines()
    else:
        lines = []

    pattern = re.compile(rf"^{re.escape(key)}\s*=")
    found = False
    new_lines = []

    for line in lines:
        if pattern.match(line):
            new_lines.append(f"{key}={value}")
            found = True
        else:
            new_lines.append(line)

    if not found:
        new_lines.append(f"{key}={value}")

    env_file.write_text("\n".join(new_lines) + "\n")


def update_env_ssl_paths(env_path: str, cert_path: str, key_path: str) -> None:
    """Update SSL_CERT and SSL_KEY in .env file."""
    update_env_value(env_path, "SSL_CERT", cert_path)
    update_env_value(env_path, "SSL_KEY", key_path)


def write_env_file(env_path: str, config: dict) -> None:
    """Write a complete .env file from a config dict.

    Backs up existing .env if present.
    """
    env_file = Path(env_path)

    # Backup existing
    if env_file.exists():
        backup = env_file.with_suffix(".env.backup")
        shutil.copy2(env_file, backup)

    lines = ["# Open Relay Portal Configuration", f"# Generated by setup wizard on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ""]

    # Group config by section
    sections = {
        "JWT": ["JWT_SECRET"],
        "Server": ["HOST", "PORT", "HOSTNAME"],
        "SSL": ["SSL_CERT", "SSL_KEY", "CERT_METHOD", "CERT_EMAIL"],
        "Database": ["DATABASE_PATH"],
        "Tokens": ["TOKEN_EXPIRY_HOURS"],
        "Rate Limiting": ["RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW"],
    }

    written_keys = set()
    for section_name, keys in sections.items():
        section_lines = []
        for key in keys:
            if key in config:
                section_lines.append(f"{key}={config[key]}")
                written_keys.add(key)
        if section_lines:
            lines.append(f"# {section_name}")
            lines.extend(section_lines)
            lines.append("")

    # Write any remaining keys not in sections
    remaining = []
    for key, value in config.items():
        if key not in written_keys:
            remaining.append(f"{key}={value}")
    if remaining:
        lines.append("# Additional Settings")
        lines.extend(remaining)
        lines.append("")

    env_file.write_text("\n".join(lines))
