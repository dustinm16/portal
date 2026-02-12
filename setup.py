"""Interactive setup wizard for Open Relay Portal.

Usage: python server.py setup
"""

import getpass
import os
import secrets
import shutil
import socket
import subprocess
import sys
from pathlib import Path

# Project root directory (where this file lives)
PROJECT_DIR = Path(__file__).parent.resolve()


def run_setup_wizard() -> None:
    """Main entry point for the interactive setup wizard."""
    _print_banner()

    env_path = PROJECT_DIR / ".env"
    existing_config = _load_existing_env(env_path) if env_path.exists() else {}

    if existing_config:
        print("Existing configuration detected (.env file found).\n")
        choice = _prompt_choice(
            "What would you like to do?",
            ["Reconfigure (update existing settings)", "Fresh setup (replace everything)"],
        )
        if choice == 2:
            existing_config = {}
            print()
    else:
        print("No existing configuration found. Starting fresh setup.\n")

    config = {}

    # --- Step 1: Hostname ---
    print("=" * 50)
    print("STEP 1: Server Hostname")
    print("=" * 50)
    default_hostname = existing_config.get("HOSTNAME", "localhost")
    hostname = _prompt_input("Enter your hostname/domain", default_hostname)
    config["HOSTNAME"] = hostname

    # Stream hostname (separate RTMPS ingress hostname, bypasses CDN)
    default_stream_host = existing_config.get("STREAM_HOSTNAME", "")
    if default_stream_host and default_stream_host != hostname:
        print(f"\n  Stream hostname (for RTMPS ingress): {default_stream_host}")
        keep_stream = _prompt_yes_no("Keep separate stream hostname?", default_yes=True)
        if keep_stream:
            config["STREAM_HOSTNAME"] = default_stream_host
        else:
            config["STREAM_HOSTNAME"] = hostname
    else:
        print("\n  (Stream hostname defaults to same as server hostname)")
        print("  Set a separate STREAM_HOSTNAME in .env if RTMPS ingress")
        print("  should bypass a CDN like Cloudflare.")

    # --- Step 2: Port ---
    print()
    print("=" * 50)
    print("STEP 2: Server Port")
    print("=" * 50)
    default_port = existing_config.get("PORT", "443")
    port = _prompt_input("Enter the HTTPS port", default_port)
    try:
        port_int = int(port)
        if port_int < 1 or port_int > 65535:
            raise ValueError
    except ValueError:
        print("  Invalid port, using 443.")
        port = "443"
    config["HOST"] = existing_config.get("HOST", "0.0.0.0")
    config["PORT"] = port

    # Check if port is available
    if not _check_port_available(int(port)):
        print(f"\n  WARNING: Port {port} is already in use.")
        print("  This is normal if Portal is already running.")
        print("  The service will be restarted after setup completes.\n")

    # --- Step 3: TLS Certificate ---
    print()
    print("=" * 50)
    print("STEP 3: TLS Certificate")
    print("=" * 50)
    print("Portal requires a TLS certificate to serve HTTPS.")
    print("Without a valid certificate, the server will not start")
    print("and browsers will show 'page took too long to respond'.\n")

    # Check for existing valid certs
    existing_cert = existing_config.get("SSL_CERT", "")
    existing_key = existing_config.get("SSL_KEY", "")
    if existing_cert and existing_key and Path(existing_cert).exists() and Path(existing_key).exists():
        print(f"  Existing certificate: {existing_cert}")
        cert_info = _get_cert_summary(existing_cert)
        if cert_info:
            print(f"  {cert_info}")
        keep_cert = _prompt_yes_no("Keep existing certificate?", default_yes=True)
        if keep_cert:
            config["SSL_CERT"] = existing_cert
            config["SSL_KEY"] = existing_key
            config["CERT_METHOD"] = existing_config.get("CERT_METHOD", "custom")
            if existing_config.get("CERT_EMAIL"):
                config["CERT_EMAIL"] = existing_config["CERT_EMAIL"]
        else:
            cert_path, key_path, cert_method = _setup_ssl(hostname, existing_config)
            config["SSL_CERT"] = cert_path
            config["SSL_KEY"] = key_path
            config["CERT_METHOD"] = cert_method
    else:
        if existing_cert and not Path(existing_cert).exists():
            print(f"  WARNING: Configured certificate not found: {existing_cert}")
            print("  This is why the server fails to start.\n")

        # On fresh install, auto-generate self-signed cert to ensure server starts
        is_fresh = not existing_config
        if is_fresh:
            print("  Auto-generating self-signed certificate for initial setup...")
            print("  (You can switch to Let's Encrypt or custom cert later)\n")
            cert_path, key_path, cert_method = _auto_generate_selfsigned(hostname)
            if cert_path:
                config["SSL_CERT"] = cert_path
                config["SSL_KEY"] = key_path
                config["CERT_METHOD"] = cert_method
                # Offer to upgrade
                upgrade = _prompt_yes_no(
                    "Would you like to configure a different certificate instead?",
                    default_yes=False,
                )
                if upgrade:
                    cert_path, key_path, cert_method = _setup_ssl(hostname, existing_config)
                    config["SSL_CERT"] = cert_path
                    config["SSL_KEY"] = key_path
                    config["CERT_METHOD"] = cert_method
            else:
                # Auto-gen failed, fall through to interactive
                cert_path, key_path, cert_method = _setup_ssl(hostname, existing_config)
                config["SSL_CERT"] = cert_path
                config["SSL_KEY"] = key_path
                config["CERT_METHOD"] = cert_method
        else:
            cert_path, key_path, cert_method = _setup_ssl(hostname, existing_config)
            config["SSL_CERT"] = cert_path
            config["SSL_KEY"] = key_path
            config["CERT_METHOD"] = cert_method

    # --- Step 4: JWT Secret ---
    print()
    print("=" * 50)
    print("STEP 4: Security")
    print("=" * 50)
    existing_secret = existing_config.get("JWT_SECRET", "")
    if existing_secret and existing_secret != "change_me_to_a_random_64_char_hex_string":
        print("  Existing JWT secret found.")
        keep = _prompt_yes_no("Keep existing JWT secret?", default_yes=True)
        if keep:
            config["JWT_SECRET"] = existing_secret
        else:
            config["JWT_SECRET"] = secrets.token_hex(32)
            print("  New JWT secret generated.")
    else:
        config["JWT_SECRET"] = secrets.token_hex(32)
        print("  JWT secret auto-generated (64-char hex).")

    # --- Database path ---
    default_db = existing_config.get("DATABASE_PATH", str(PROJECT_DIR / "portal.db"))
    config["DATABASE_PATH"] = default_db

    # Carry over ALL existing settings not already set by the wizard
    # This preserves any custom env vars the user added manually
    for key, value in existing_config.items():
        if key not in config:
            config[key] = value

    # --- Step 5: Write .env ---
    print()
    print("=" * 50)
    print("STEP 5: Writing Configuration")
    print("=" * 50)
    _write_env(env_path, config)
    print(f"  Configuration written to: {env_path}")

    # --- Step 6: Virtual Environment & Dependencies ---
    print()
    print("=" * 50)
    print("STEP 6: Dependencies")
    print("=" * 50)
    venv_python = _setup_venv_and_deps()

    # --- Step 7: MediaMTX (streaming) ---
    print()
    print("=" * 50)
    print("STEP 7: MediaMTX (Streaming Server)")
    print("=" * 50)
    _setup_mediamtx()

    # --- Step 8: Admin User ---
    print()
    print("=" * 50)
    print("STEP 8: Admin User")
    print("=" * 50)
    _setup_admin_user(venv_python)

    # --- Step 9: Systemd Service ---
    print()
    print("=" * 50)
    print("STEP 9: Systemd Service")
    print("=" * 50)
    _setup_systemd(venv_python)

    # --- Step 10: Verify Configuration ---
    print()
    print("=" * 50)
    print("STEP 10: Verification")
    print("=" * 50)
    _verify_setup(config)

    # --- Summary ---
    _print_summary(config, venv_python)


def _print_banner() -> None:
    """Print the setup wizard banner."""
    print()
    print("=" * 50)
    print("  Open Relay Portal - Setup Wizard")
    print("=" * 50)
    print()
    print("This wizard will guide you through the initial")
    print("configuration of Open Relay Portal.")
    print()


def _prompt_input(prompt: str, default: str = "") -> str:
    """Prompt for text input with optional default."""
    if default:
        result = input(f"  {prompt} [{default}]: ").strip()
        return result if result else default
    else:
        while True:
            result = input(f"  {prompt}: ").strip()
            if result:
                return result
            print("  (Value required)")


def _prompt_choice(prompt: str, options: list[str]) -> int:
    """Prompt user to select from numbered options. Returns 1-based index."""
    print(f"  {prompt}\n")
    for i, opt in enumerate(options, 1):
        print(f"    {i}) {opt}")
    print()

    while True:
        try:
            choice = int(input(f"  Enter choice [1-{len(options)}]: "))
            if 1 <= choice <= len(options):
                return choice
        except (ValueError, EOFError):
            pass
        print(f"  Please enter a number between 1 and {len(options)}.")


def _prompt_yes_no(prompt: str, default_yes: bool = True) -> bool:
    """Prompt for yes/no answer."""
    suffix = "[Y/n]" if default_yes else "[y/N]"
    result = input(f"  {prompt} {suffix}: ").strip().lower()
    if not result:
        return default_yes
    return result in ("y", "yes")


def _load_existing_env(env_path: Path) -> dict:
    """Load existing .env file as a dict."""
    config = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            config[key.strip()] = value.strip()
    return config


def _check_port_available(port: int) -> bool:
    """Check if a TCP port is available to bind."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.bind(("0.0.0.0", port))
            return True
    except OSError:
        return False


def _get_cert_summary(cert_path: str) -> str:
    """Get a one-line summary of a certificate, or empty string on error."""
    try:
        import cert_manager
        info = cert_manager.get_cert_info(cert_path)
        cn = info.get("subject", {}).get("CN", "unknown")
        days = info.get("days_until_expiry", 0)
        method = info.get("method", "unknown")
        if days <= 0:
            return f"  CN={cn}, method={method}, EXPIRED"
        return f"  CN={cn}, method={method}, expires in {days} days"
    except Exception:
        return ""


def _auto_generate_selfsigned(hostname: str) -> tuple[str, str, str]:
    """Auto-generate a self-signed cert without user interaction.

    Tries cert_manager first, then openssl CLI as fallback.
    Returns (cert_path, key_path, "selfsigned") or ("", "", "") on failure.
    """
    certs_dir = str(PROJECT_DIR / "certs")

    # Try cert_manager (Python cryptography library)
    if _check_cryptography_available():
        try:
            import cert_manager
            cert_path, key_path = cert_manager.generate_self_signed_cert(
                hostname, certs_dir, validity_days=365
            )
            if Path(cert_path).exists() and Path(key_path).exists():
                print(f"  Certificate: {cert_path}")
                print(f"  Private key: {key_path}")
                print()
                print("  NOTE: Self-signed certificates cause browser warnings.")
                print("  Users must click 'Advanced' > 'Proceed' on first visit.")
                print("  For production, switch to Let's Encrypt via Admin Panel.\n")
                return cert_path, key_path, "selfsigned"
        except Exception as e:
            print(f"  cert_manager failed: {e}")

    # Fallback: openssl CLI
    if shutil.which("openssl"):
        try:
            Path(certs_dir).mkdir(parents=True, exist_ok=True)
            cert_path = str(Path(certs_dir) / "selfsigned_cert.pem")
            key_path = str(Path(certs_dir) / "selfsigned_key.pem")

            result = subprocess.run(
                [
                    "openssl", "req", "-x509", "-newkey", "rsa:4096",
                    "-keyout", key_path, "-out", cert_path,
                    "-sha256", "-days", "365", "-nodes",
                    "-subj", f"/CN={hostname}/O=Open Relay Portal/OU=Self-Signed",
                    "-addext", f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1",
                ],
                capture_output=True, text=True,
            )
            if result.returncode == 0 and Path(cert_path).exists():
                os.chmod(key_path, 0o600)
                os.chmod(cert_path, 0o644)
                print(f"  Certificate: {cert_path}")
                print(f"  Private key: {key_path}")
                print()
                print("  NOTE: Self-signed certificates cause browser warnings.")
                print("  Users must click 'Advanced' > 'Proceed' on first visit.")
                print("  For production, switch to Let's Encrypt via Admin Panel.\n")
                return cert_path, key_path, "selfsigned"
            else:
                print(f"  openssl failed: {result.stderr.strip()}")
        except Exception as e:
            print(f"  openssl failed: {e}")

    # Both methods failed
    print("  Could not auto-generate certificate.")
    print("  Neither Python cryptography nor openssl are available.\n")
    return "", "", ""


def _check_cryptography_available() -> bool:
    """Check if the cryptography library is importable."""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def _install_cryptography() -> bool:
    """Attempt to install the cryptography library. Returns True on success."""
    print("  Installing cryptography library...")
    venv_pip = PROJECT_DIR / "venv" / "bin" / "pip"
    pip_cmd = str(venv_pip) if venv_pip.exists() else "pip3"

    result = subprocess.run(
        [pip_cmd, "install", "cryptography", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        print("  cryptography installed successfully.")
        return True
    else:
        # Try system pip
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "cryptography", "-q"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("  cryptography installed successfully.")
            return True
        print(f"  ERROR: Failed to install cryptography: {result.stderr.strip()}")
        return False


def _setup_ssl(hostname: str, existing_config: dict) -> tuple[str, str, str]:
    """Set up SSL based on user's choice. Returns (cert_path, key_path, method)."""
    certs_dir = str(PROJECT_DIR / "certs")

    print("  How would you like to handle TLS certificates?\n")
    ssl_choice = _prompt_choice(
        "Select certificate method:",
        [
            "Self-signed (auto-generate, good for dev/LAN)",
            "Let's Encrypt (free trusted cert, requires public DNS + port 80)",
            "Custom certificate (bring your own cert files)",
        ],
    )

    if ssl_choice == 1:
        return _setup_ssl_selfsigned(hostname, certs_dir, existing_config)
    elif ssl_choice == 2:
        return _setup_ssl_letsencrypt(hostname, certs_dir, existing_config)
    else:
        return _setup_ssl_custom(hostname, existing_config)


def _setup_ssl_selfsigned(
    hostname: str, certs_dir: str, existing_config: dict
) -> tuple[str, str, str]:
    """Generate a self-signed certificate."""
    print("\n  Generating self-signed certificate...")

    # Ensure cryptography is available
    if not _check_cryptography_available():
        print("  The 'cryptography' Python library is required.")
        install = _prompt_yes_no("Install it now?", default_yes=True)
        if install:
            if not _install_cryptography():
                print("\n  Cannot generate certificate without cryptography library.")
                print("  Falling back to openssl command-line tool...\n")
                return _setup_ssl_selfsigned_openssl(hostname, certs_dir)
        else:
            print("  Trying openssl command-line tool instead...\n")
            return _setup_ssl_selfsigned_openssl(hostname, certs_dir)

    try:
        import cert_manager
        cert_path, key_path = cert_manager.generate_self_signed_cert(
            hostname, certs_dir, validity_days=365
        )
        # Verify the files were actually created
        if not Path(cert_path).exists() or not Path(key_path).exists():
            raise FileNotFoundError("Certificate files were not created")

        print(f"  Certificate: {cert_path}")
        print(f"  Private key: {key_path}")
        print()
        print("  NOTE: Self-signed certificates cause browser warnings.")
        print("  Users must click 'Advanced' > 'Proceed' on first visit.")
        print("  For production, use Let's Encrypt or a trusted CA.")
        return cert_path, key_path, "selfsigned"
    except Exception as e:
        print(f"  ERROR: cert_manager failed: {e}")
        print("  Trying openssl command-line tool...\n")
        return _setup_ssl_selfsigned_openssl(hostname, certs_dir)


def _setup_ssl_selfsigned_openssl(
    hostname: str, certs_dir: str
) -> tuple[str, str, str]:
    """Fallback: generate self-signed cert using openssl CLI."""
    if not shutil.which("openssl"):
        print("  ERROR: Neither cryptography library nor openssl found.")
        print("  Install one of:")
        print("    pip install cryptography")
        print("    apt install openssl")
        print()
        print("  Setup cannot continue without TLS certificates.")
        sys.exit(1)

    Path(certs_dir).mkdir(parents=True, exist_ok=True)
    cert_path = str(Path(certs_dir) / "selfsigned_cert.pem")
    key_path = str(Path(certs_dir) / "selfsigned_key.pem")

    # Generate with openssl
    result = subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:4096",
            "-keyout", key_path, "-out", cert_path,
            "-sha256", "-days", "365", "-nodes",
            "-subj", f"/CN={hostname}/O=Open Relay Portal/OU=Self-Signed",
            "-addext", f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1",
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(f"  ERROR: openssl failed: {result.stderr.strip()}")
        print("  Setup cannot continue without TLS certificates.")
        sys.exit(1)

    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)

    # Verify files exist
    if not Path(cert_path).exists() or not Path(key_path).exists():
        print("  ERROR: Certificate files were not created.")
        sys.exit(1)

    print(f"  Certificate: {cert_path}")
    print(f"  Private key: {key_path}")
    print()
    print("  NOTE: Self-signed certificates cause browser warnings.")
    print("  Users must click 'Advanced' > 'Proceed' on first visit.")
    return cert_path, key_path, "selfsigned"


def _setup_ssl_letsencrypt(
    hostname: str, certs_dir: str, existing_config: dict
) -> tuple[str, str, str]:
    """Obtain a Let's Encrypt certificate."""
    print()

    # Pre-flight checks
    problems = []

    # Check certbot installed
    if not shutil.which("certbot"):
        problems.append("certbot is not installed (install with: sudo apt install certbot)")

    # Check hostname isn't localhost/IP
    if hostname in ("localhost", "127.0.0.1", "::1") or hostname.startswith("192.168.") or hostname.startswith("10."):
        problems.append(f"'{hostname}' is a local address — Let's Encrypt requires a public domain name")

    # Check port 80 available (needed for HTTP-01 challenge)
    if not _check_port_available(80):
        # Check what's using it
        port80_user = _get_port_user(80)
        if port80_user:
            problems.append(f"Port 80 is in use by {port80_user} — Let's Encrypt needs port 80 for verification")
        else:
            problems.append("Port 80 is in use — Let's Encrypt needs port 80 for HTTP challenge")

    # Check running as root (certbot typically needs root)
    if os.geteuid() != 0:
        problems.append("Not running as root — certbot usually requires sudo")

    if problems:
        print("  Pre-flight checks found issues:\n")
        for p in problems:
            print(f"    - {p}")
        print()
        proceed = _prompt_yes_no("Try anyway?", default_yes=False)
        if not proceed:
            print()
            retry = _prompt_choice(
                "Select alternative:",
                ["Self-signed (recommended)", "Custom certificate", "Exit setup"],
            )
            if retry == 1:
                return _setup_ssl_selfsigned(hostname, certs_dir, existing_config)
            elif retry == 2:
                return _setup_ssl_custom(hostname, existing_config)
            else:
                sys.exit(1)

    email = _prompt_input("Enter email for Let's Encrypt notifications")
    config_email_holder = {"CERT_EMAIL": email}

    print(f"\n  Requesting certificate for {hostname}...")
    print("  This may take 30-60 seconds...\n")

    try:
        import cert_manager
        success, message = cert_manager.request_letsencrypt_cert(hostname, email)
        if success:
            cert_path, key_path = cert_manager.get_letsencrypt_cert_paths(hostname)

            # Verify cert files exist
            if not Path(cert_path).exists():
                print(f"  ERROR: Certificate file not found after issuance: {cert_path}")
                print("  certbot may have saved to a different path.")
                # Try to find it
                found = _find_letsencrypt_cert(hostname)
                if found:
                    cert_path, key_path = found
                    print(f"  Found certificate at: {cert_path}")
                else:
                    print("  Falling back to self-signed.")
                    return _setup_ssl_selfsigned(hostname, certs_dir, existing_config)

            cert_manager.install_renewal_hook("portal")
            print(f"  Success! Certificate issued.")
            print(f"  Certificate: {cert_path}")
            print(f"  Private key: {key_path}")
            print(f"  Auto-renewal hook installed.")

            # Store email for renewal notifications
            return cert_path, key_path, "letsencrypt"
        else:
            print(f"  ERROR: {message}")
            print()
            retry = _prompt_choice(
                "Select alternative:",
                ["Self-signed (recommended)", "Custom certificate", "Exit setup"],
            )
            if retry == 1:
                return _setup_ssl_selfsigned(hostname, certs_dir, existing_config)
            elif retry == 2:
                return _setup_ssl_custom(hostname, existing_config)
            else:
                sys.exit(1)
    except ImportError:
        print("  ERROR: cryptography library not available for cert validation.")
        print("  Attempting certbot directly...\n")

        # Run certbot directly without cert_manager
        if shutil.which("certbot"):
            result = subprocess.run(
                [
                    "certbot", "certonly", "--non-interactive", "--agree-tos",
                    "--email", email, "-d", hostname,
                    "--standalone", "--preferred-challenges", "http",
                ],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                cert_path = f"/etc/letsencrypt/live/{hostname}/fullchain.pem"
                key_path = f"/etc/letsencrypt/live/{hostname}/privkey.pem"
                if Path(cert_path).exists():
                    print(f"  Success! Certificate issued.")
                    print(f"  Certificate: {cert_path}")
                    print(f"  Private key: {key_path}")
                    return cert_path, key_path, "letsencrypt"

            error = result.stderr.strip() or result.stdout.strip()
            print(f"  ERROR: certbot failed: {error}")

        print()
        retry = _prompt_choice(
            "Select alternative:",
            ["Self-signed (recommended)", "Custom certificate", "Exit setup"],
        )
        if retry == 1:
            return _setup_ssl_selfsigned(hostname, certs_dir, existing_config)
        elif retry == 2:
            return _setup_ssl_custom(hostname, existing_config)
        else:
            sys.exit(1)


def _setup_ssl_custom(
    hostname: str, existing_config: dict
) -> tuple[str, str, str]:
    """Configure custom certificate paths."""
    print()
    default_cert = existing_config.get("SSL_CERT", "")
    default_key = existing_config.get("SSL_KEY", "")

    cert_path = _prompt_input(
        "Path to certificate PEM file",
        default_cert if default_cert else ""
    )
    key_path = _prompt_input(
        "Path to private key PEM file",
        default_key if default_key else ""
    )

    # Validate files exist
    if not Path(cert_path).exists():
        print(f"\n  ERROR: Certificate file not found: {cert_path}")
        retry = _prompt_yes_no("Re-enter paths?", default_yes=True)
        if retry:
            return _setup_ssl_custom(hostname, existing_config)
        else:
            print("  WARNING: Server will fail to start without valid certificate.")

    if not Path(key_path).exists():
        print(f"\n  ERROR: Key file not found: {key_path}")
        retry = _prompt_yes_no("Re-enter paths?", default_yes=True)
        if retry:
            return _setup_ssl_custom(hostname, existing_config)
        else:
            print("  WARNING: Server will fail to start without valid key.")

    # Validate the pair if both exist
    if Path(cert_path).exists() and Path(key_path).exists():
        try:
            import cert_manager
            cert_data = Path(cert_path).read_bytes()
            key_data = Path(key_path).read_bytes()
            is_valid, error = cert_manager.validate_cert_key_pair(cert_data, key_data)
            if is_valid:
                info = _get_cert_summary(cert_path)
                print(f"  Certificate and key validated successfully.")
                if info:
                    print(f"  {info}")
            else:
                print(f"  WARNING: {error}")
                print("  The server may fail to start with mismatched cert/key.")
        except ImportError:
            # Try openssl verify as fallback
            result = subprocess.run(
                ["openssl", "x509", "-in", cert_path, "-noout", "-dates"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(f"  Certificate readable. Dates: {result.stdout.strip()}")
            else:
                print("  Could not validate certificate (cryptography library not available).")
        except Exception as e:
            print(f"  WARNING: Validation error: {e}")

    return cert_path, key_path, "custom"


def _find_letsencrypt_cert(hostname: str) -> tuple[str, str] | None:
    """Search for Let's Encrypt cert in common locations."""
    candidates = [
        (f"/etc/letsencrypt/live/{hostname}/fullchain.pem",
         f"/etc/letsencrypt/live/{hostname}/privkey.pem"),
        (f"/etc/letsencrypt/live/{hostname}-0001/fullchain.pem",
         f"/etc/letsencrypt/live/{hostname}-0001/privkey.pem"),
    ]
    for cert, key in candidates:
        if Path(cert).exists() and Path(key).exists():
            return cert, key
    return None


def _get_port_user(port: int) -> str:
    """Get the process name using a given port, or empty string."""
    try:
        result = subprocess.run(
            ["ss", "-tlnp", f"sport = :{port}"],
            capture_output=True, text=True, timeout=5,
        )
        for line in result.stdout.splitlines()[1:]:  # Skip header
            if f":{port}" in line:
                # Extract process name from users:(("name",pid=...))
                if 'users:' in line:
                    start = line.index('users:')
                    return line[start:].split('"')[1] if '"' in line[start:] else "unknown"
        return ""
    except Exception:
        return ""


def _write_env(env_path: Path, config: dict) -> None:
    """Write .env file from config dict, backing up existing."""
    if env_path.exists():
        backup = env_path.with_name(".env.backup")
        shutil.copy2(env_path, backup)
        print(f"  Existing .env backed up to: {backup}")

    lines = [
        "# Open Relay Portal Configuration",
        f"# Generated by setup wizard",
        "",
        "# JWT Authentication",
        f"JWT_SECRET={config.get('JWT_SECRET', '')}",
        "",
        "# Server",
        f"HOST={config.get('HOST', '0.0.0.0')}",
        f"PORT={config.get('PORT', '443')}",
        f"HOSTNAME={config.get('HOSTNAME', 'localhost')}",
    ]

    if config.get("STREAM_HOSTNAME") and config["STREAM_HOSTNAME"] != config.get("HOSTNAME"):
        lines.append(f"STREAM_HOSTNAME={config['STREAM_HOSTNAME']}")

    lines.extend([
        "",
        "# TLS Certificate",
        f"SSL_CERT={config.get('SSL_CERT', '')}",
        f"SSL_KEY={config.get('SSL_KEY', '')}",
        f"CERT_METHOD={config.get('CERT_METHOD', '')}",
    ])

    if config.get("CERT_EMAIL"):
        lines.append(f"CERT_EMAIL={config['CERT_EMAIL']}")

    lines.extend([
        "",
        "# Database",
        f"DATABASE_PATH={config.get('DATABASE_PATH', str(PROJECT_DIR / 'portal.db'))}",
    ])

    # Add optional settings that exist
    optional_lines = []
    optional_keys = {
        "TOKEN_EXPIRY_HOURS": "Token Expiry",
        "RATE_LIMIT_REQUESTS": "Rate Limiting",
        "RATE_LIMIT_WINDOW": "Rate Limiting",
        "SHODAN_API_KEY": "Shodan",
        "RTMP_PLAIN_ENABLED": "RTMP",
        "RTMP_PLAIN_PORT": "RTMP",
        "STUN_SERVER": "Voice Chat",
        "TURN_SERVER": "Voice Chat",
        "TURN_USERNAME": "Voice Chat",
        "TURN_PASSWORD": "Voice Chat",
    }
    current_section = None
    for key, section in optional_keys.items():
        if key in config and config[key]:
            if section != current_section:
                optional_lines.append("")
                optional_lines.append(f"# {section}")
                current_section = section
            optional_lines.append(f"{key}={config[key]}")

    lines.extend(optional_lines)

    # Write any extra keys not already covered (user-added custom vars)
    written_keys = {
        "JWT_SECRET", "HOST", "PORT", "HOSTNAME", "STREAM_HOSTNAME",
        "SSL_CERT", "SSL_KEY", "CERT_METHOD", "CERT_EMAIL", "DATABASE_PATH",
    }
    written_keys.update(optional_keys.keys())
    extra_keys = sorted(k for k in config if k not in written_keys and config[k])
    if extra_keys:
        lines.append("")
        lines.append("# Additional settings")
        for key in extra_keys:
            lines.append(f"{key}={config[key]}")

    lines.append("")

    env_path.write_text("\n".join(lines))
    os.chmod(str(env_path), 0o600)


MEDIAMTX_VERSION = "1.9.3"
MEDIAMTX_URL = (
    f"https://github.com/bluenviron/mediamtx/releases/download/"
    f"v{MEDIAMTX_VERSION}/mediamtx_v{MEDIAMTX_VERSION}_linux_amd64.tar.gz"
)


def install_mediamtx(install_dir: str = "/usr/local/bin", version: str = None) -> bool:
    """Download and install MediaMTX binary. Returns True on success."""
    import tarfile
    import tempfile
    import urllib.request

    version = version or MEDIAMTX_VERSION
    url = (
        f"https://github.com/bluenviron/mediamtx/releases/download/"
        f"v{version}/mediamtx_v{version}_linux_amd64.tar.gz"
    )
    dest = Path(install_dir) / "mediamtx"

    print(f"  Downloading MediaMTX v{version}...")
    print(f"  URL: {url}")

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tarball = Path(tmpdir) / "mediamtx.tar.gz"

            # Download
            urllib.request.urlretrieve(url, str(tarball))
            print(f"  Downloaded ({tarball.stat().st_size // 1024 // 1024} MB)")

            # Extract just the binary
            with tarfile.open(str(tarball), "r:gz") as tar:
                members = [m for m in tar.getmembers() if m.name == "mediamtx"]
                if not members:
                    # Try any member that looks like the binary
                    members = [m for m in tar.getmembers() if "mediamtx" in m.name and not m.name.endswith(".yml")]
                if not members:
                    print("  ERROR: mediamtx binary not found in archive")
                    return False
                tar.extract(members[0], tmpdir)
                extracted = Path(tmpdir) / members[0].name

                # Install to destination
                is_root = os.geteuid() == 0
                if is_root:
                    shutil.copy2(str(extracted), str(dest))
                    os.chmod(str(dest), 0o755)
                else:
                    result = subprocess.run(
                        ["sudo", "cp", str(extracted), str(dest)],
                        capture_output=True, text=True,
                    )
                    if result.returncode != 0:
                        print(f"  ERROR: Failed to install: {result.stderr.strip()}")
                        return False
                    subprocess.run(["sudo", "chmod", "755", str(dest)],
                                   capture_output=True, text=True)

        # Verify
        result = subprocess.run([str(dest), "--help"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 or "mediamtx" in (result.stdout + result.stderr).lower():
            print(f"  Installed: {dest}")
            return True
        else:
            print(f"  WARNING: Binary installed but verification failed")
            return True

    except urllib.error.HTTPError as e:
        print(f"  ERROR: Download failed: HTTP {e.code}")
        print(f"  Check that version v{version} exists at:")
        print(f"    https://github.com/bluenviron/mediamtx/releases")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def _setup_mediamtx() -> None:
    """Check for MediaMTX and offer to install if missing."""
    existing = shutil.which("mediamtx")

    if existing:
        print(f"  MediaMTX found: {existing}")
        # Try to get version
        try:
            result = subprocess.run(
                [existing, "--help"], capture_output=True, text=True, timeout=5,
            )
            output = result.stdout + result.stderr
            if "v" in output:
                for line in output.splitlines():
                    if line.strip().startswith("mediamtx") or "v" in line.lower():
                        print(f"  {line.strip()}")
                        break
        except Exception:
            pass

        reinstall = _prompt_yes_no(
            f"Reinstall/update to v{MEDIAMTX_VERSION}?", default_yes=False,
        )
        if not reinstall:
            print("  Keeping existing installation.")
            return

    else:
        print("  MediaMTX is not installed.")
        print("  MediaMTX is required for live streaming (RTMPS/HLS).")
        print(f"  Version: v{MEDIAMTX_VERSION}\n")
        install = _prompt_yes_no("Download and install MediaMTX?", default_yes=True)
        if not install:
            print("  Skipped. Streaming features will not work without MediaMTX.")
            print("  Install later with: sudo python server.py install-mediamtx")
            return

    if install_mediamtx():
        print("  MediaMTX is ready for streaming.")
    else:
        print("  MediaMTX installation failed.")
        print("  Install manually: https://github.com/bluenviron/mediamtx/releases")
        print("  Or retry: sudo python server.py install-mediamtx")


def _setup_venv_and_deps() -> str:
    """Create venv if missing and install dependencies. Returns python path."""
    venv_dir = PROJECT_DIR / "venv"
    venv_python = str(venv_dir / "bin" / "python")
    requirements = PROJECT_DIR / "requirements.txt"

    if venv_dir.exists() and Path(venv_python).exists():
        print(f"  Virtual environment found: {venv_dir}")
        install = _prompt_yes_no("Install/update dependencies?", default_yes=True)
        if install and requirements.exists():
            print("  Installing dependencies...")
            result = subprocess.run(
                [venv_python, "-m", "pip", "install", "-r", str(requirements), "-q"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print("  Dependencies installed successfully.")
            else:
                print(f"  WARNING: pip install failed: {result.stderr.strip()}")
    else:
        print(f"  No virtual environment found at {venv_dir}")
        create = _prompt_yes_no("Create virtual environment and install dependencies?", default_yes=True)
        if create:
            print("  Creating virtual environment...")
            result = subprocess.run(
                [sys.executable, "-m", "venv", str(venv_dir)],
                capture_output=True, text=True,
            )
            if result.returncode != 0:
                print(f"  ERROR: Failed to create venv: {result.stderr.strip()}")
                print(f"  Using current Python: {sys.executable}")
                return sys.executable

            if requirements.exists():
                print("  Installing dependencies...")
                result = subprocess.run(
                    [venv_python, "-m", "pip", "install", "-r", str(requirements), "-q"],
                    capture_output=True, text=True,
                )
                if result.returncode == 0:
                    print("  Dependencies installed successfully.")
                else:
                    print(f"  WARNING: pip install failed: {result.stderr.strip()}")
        else:
            venv_python = sys.executable
            print(f"  Using current Python: {venv_python}")

    return venv_python


def _setup_admin_user(venv_python: str) -> None:
    """Set up the initial admin user (creates or resets password)."""
    print("  Initializing admin user...")
    result = subprocess.run(
        [venv_python, str(PROJECT_DIR / "server.py"), "init"],
        capture_output=True, text=True, cwd=str(PROJECT_DIR),
    )
    output = result.stdout.strip() or result.stderr.strip()
    if output:
        print(output)


def _generate_systemd_service(venv_python: str) -> str:
    """Generate systemd service file content with correct paths."""
    return f"""[Unit]
Description=Open Relay Portal - WebSocket Auth and Relay Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory={PROJECT_DIR}
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart={venv_python} {PROJECT_DIR}/server.py serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
PrivateTmp=true

# Note: Running as root with full capabilities for terminal plugin
# The terminal spawns shells that need setuid/setgid for apt and other tools
# Do NOT add CapabilityBoundingSet or NoNewPrivileges as they break terminal functionality

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=portal

[Install]
WantedBy=multi-user.target
"""


def _setup_systemd(venv_python: str) -> None:
    """Generate and optionally install systemd service."""
    service_content = _generate_systemd_service(venv_python)

    # Write to project directory first
    local_service = PROJECT_DIR / "portal.service"
    local_service.write_text(service_content)
    print(f"  Service file generated: {local_service}")

    install = _prompt_yes_no("Install systemd service and enable?", default_yes=True)
    if not install:
        print("  Skipped. Install manually with:")
        print(f"    sudo cp {local_service} /etc/systemd/system/")
        print("    sudo systemctl daemon-reload && sudo systemctl enable portal")
        return

    is_root = os.geteuid() == 0
    use_sudo = not is_root

    if use_sudo:
        print("  Not running as root — will use sudo for service installation.")
        print("  (You may be prompted for your password)\n")

    # Copy to systemd
    target = "/etc/systemd/system/portal.service"
    if is_root:
        shutil.copy2(local_service, target)
    else:
        result = subprocess.run(
            ["sudo", "cp", str(local_service), target],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            print(f"  ERROR: Failed to copy service file: {result.stderr.strip()}")
            print(f"  Install manually with:")
            print(f"    sudo cp {local_service} /etc/systemd/system/")
            print(f"    sudo systemctl daemon-reload && sudo systemctl enable --now portal")
            return
    print(f"  Installed to: {target}")

    # Daemon reload
    _run_systemctl(["daemon-reload"], use_sudo)
    print("  systemd reloaded.")

    # Enable
    _run_systemctl(["enable", "portal"], use_sudo)
    print("  Service enabled (will start on boot).")

    start = _prompt_yes_no("Start the portal service now?", default_yes=True)
    if start:
        result = _run_systemctl(["restart", "portal"], use_sudo)
        if result.returncode == 0:
            print("  Portal service started!")
            # Give it a moment to start then check status
            import time
            time.sleep(3)
            status = _run_systemctl(["is-active", "portal"], use_sudo)
            if status.stdout.strip() == "active":
                print("  Service status: RUNNING")
            else:
                print(f"  Service status: {status.stdout.strip()}")
                print("  Check logs with: sudo journalctl -u portal -f")
        else:
            print(f"  WARNING: Failed to start: {result.stderr.strip()}")
            print("  Check logs with: sudo journalctl -u portal -f")


def _run_systemctl(args: list[str], use_sudo: bool = False) -> subprocess.CompletedProcess:
    """Run a systemctl command, optionally with sudo."""
    cmd = ["sudo", "systemctl"] if use_sudo else ["systemctl"]
    cmd.extend(args)
    return subprocess.run(cmd, capture_output=True, text=True)


def _verify_setup(config: dict) -> None:
    """Verify the setup configuration is valid and the server can start."""
    issues = []
    warnings = []

    # Check .env exists
    env_path = PROJECT_DIR / ".env"
    if not env_path.exists():
        issues.append(".env file not found")

    # Check certificate files
    cert_path = config.get("SSL_CERT", "")
    key_path = config.get("SSL_KEY", "")

    if not cert_path:
        issues.append("SSL_CERT is not set")
    elif not Path(cert_path).exists():
        issues.append(f"Certificate file not found: {cert_path}")
    else:
        # Check cert readability
        try:
            Path(cert_path).read_bytes()
        except PermissionError:
            issues.append(f"Cannot read certificate file (permission denied): {cert_path}")

    if not key_path:
        issues.append("SSL_KEY is not set")
    elif not Path(key_path).exists():
        issues.append(f"Private key file not found: {key_path}")
    else:
        try:
            Path(key_path).read_bytes()
        except PermissionError:
            issues.append(f"Cannot read private key file (permission denied): {key_path}")

    # Check key permissions (should be 0o600)
    if key_path and Path(key_path).exists():
        mode = oct(Path(key_path).stat().st_mode)[-3:]
        if mode != "600":
            warnings.append(f"Private key permissions are {mode} (should be 600)")

    # Check JWT secret
    jwt = config.get("JWT_SECRET", "")
    if not jwt or jwt == "change_me_to_a_random_64_char_hex_string":
        issues.append("JWT_SECRET is not set or is the default placeholder")
    elif len(jwt) < 32:
        warnings.append("JWT_SECRET should be at least 32 characters")

    # Check database path is writable
    db_path = Path(config.get("DATABASE_PATH", str(PROJECT_DIR / "portal.db")))
    db_dir = db_path.parent
    if not db_dir.exists():
        warnings.append(f"Database directory does not exist: {db_dir}")
    elif not os.access(str(db_dir), os.W_OK):
        issues.append(f"Database directory is not writable: {db_dir}")

    # Check venv
    venv_python = PROJECT_DIR / "venv" / "bin" / "python"
    if not venv_python.exists():
        warnings.append("Virtual environment not found at venv/")

    # Report
    if issues:
        print("  ISSUES (will prevent server from starting):\n")
        for issue in issues:
            print(f"    [!] {issue}")
        print()

    if warnings:
        print("  WARNINGS:\n")
        for w in warnings:
            print(f"    [~] {w}")
        print()

    if not issues and not warnings:
        print("  All checks passed! Configuration looks good.")
    elif not issues:
        print("  No critical issues found. Server should start successfully.")


def _print_summary(config: dict, venv_python: str) -> None:
    """Print setup completion summary."""
    print()
    print("=" * 50)
    print("  Setup Complete!")
    print("=" * 50)
    print()
    print(f"  Hostname:    {config.get('HOSTNAME', 'localhost')}")
    print(f"  Port:        {config.get('PORT', '443')}")
    print(f"  Certificate: {config.get('CERT_METHOD', 'unknown')}")
    print(f"  SSL Cert:    {config.get('SSL_CERT', 'not set')}")
    print(f"  Database:    {config.get('DATABASE_PATH', 'portal.db')}")
    print(f"  Python:      {venv_python}")
    print()
    print("  Configuration saved to: .env")
    print()
    print("  Quick Commands:")
    print("    sudo systemctl status portal    # Check status")
    print("    sudo systemctl restart portal   # Restart")
    print("    sudo journalctl -u portal -f    # View logs")
    print()

    hostname = config.get("HOSTNAME", "localhost")
    port = config.get("PORT", "443")
    cert_method = config.get("CERT_METHOD", "")

    if port == "443":
        print(f"  Open in browser: https://{hostname}")
    else:
        print(f"  Open in browser: https://{hostname}:{port}")

    if cert_method == "selfsigned":
        print()
        print("  IMPORTANT: Since you're using a self-signed certificate,")
        print("  your browser will show a security warning on first visit.")
        print("  Click 'Advanced' > 'Proceed to site' to continue.")
    print()

    # Troubleshooting hint
    print("  If you see 'page took too long to respond':")
    print("    1. Check if portal is running: sudo systemctl status portal")
    print("    2. Check logs for TLS errors: sudo journalctl -u portal -n 50")
    print("    3. Verify cert exists: ls -la " + config.get("SSL_CERT", "/path/to/cert"))
    print("    4. Re-run setup: sudo python server.py setup")
    print()


if __name__ == "__main__":
    run_setup_wizard()
