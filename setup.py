"""Interactive setup wizard for Open Relay Portal.

Usage: python server.py setup
"""

import getpass
import os
import secrets
import shutil
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
    hostname = _prompt_input(f"Enter your hostname/domain", default_hostname)
    config["HOSTNAME"] = hostname

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
        print("Invalid port, using 443.")
        port = "443"
    config["HOST"] = existing_config.get("HOST", "0.0.0.0")
    config["PORT"] = port

    # --- Step 3: SSL Certificate ---
    print()
    print("=" * 50)
    print("STEP 3: TLS Certificate")
    print("=" * 50)
    print("How would you like to handle TLS certificates?\n")
    ssl_choice = _prompt_choice(
        "Select certificate method:",
        [
            "Self-signed (auto-generate, good for dev/LAN)",
            "Let's Encrypt (free trusted cert, requires public DNS)",
            "Custom certificate (bring your own cert files)",
        ],
    )

    cert_path, key_path, cert_method = _setup_ssl(ssl_choice, hostname, existing_config)
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
        print("Existing JWT secret found.")
        keep = _prompt_yes_no("Keep existing JWT secret?", default_yes=True)
        if keep:
            config["JWT_SECRET"] = existing_secret
        else:
            config["JWT_SECRET"] = secrets.token_hex(32)
            print("New JWT secret generated.")
    else:
        config["JWT_SECRET"] = secrets.token_hex(32)
        print("JWT secret auto-generated (64-char hex).")

    # --- Step 5: Database ---
    default_db = existing_config.get("DATABASE_PATH", str(PROJECT_DIR / "portal.db"))
    config["DATABASE_PATH"] = default_db

    # Carry over other existing settings
    carry_over_keys = [
        "TOKEN_EXPIRY_HOURS", "RATE_LIMIT_REQUESTS", "RATE_LIMIT_WINDOW",
        "SHODAN_API_KEY", "RTMP_PLAIN_ENABLED", "RTMP_PLAIN_PORT",
        "STUN_SERVER", "TURN_SERVER", "TURN_USERNAME", "TURN_PASSWORD",
        "CERT_EMAIL",
    ]
    for key in carry_over_keys:
        if key in existing_config:
            config[key] = existing_config[key]

    # --- Step 6: Write .env ---
    print()
    print("=" * 50)
    print("STEP 5: Writing Configuration")
    print("=" * 50)
    _write_env(env_path, config)
    print(f"Configuration written to: {env_path}")

    # --- Step 7: Virtual Environment & Dependencies ---
    print()
    print("=" * 50)
    print("STEP 6: Dependencies")
    print("=" * 50)
    venv_python = _setup_venv_and_deps()

    # --- Step 8: Admin User ---
    print()
    print("=" * 50)
    print("STEP 7: Admin User")
    print("=" * 50)
    _setup_admin_user(venv_python)

    # --- Step 9: Systemd Service ---
    print()
    print("=" * 50)
    print("STEP 8: Systemd Service"   )
    print("=" * 50)
    _setup_systemd(venv_python)

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


def _setup_ssl(choice: int, hostname: str, existing_config: dict) -> tuple[str, str, str]:
    """Set up SSL based on user's choice. Returns (cert_path, key_path, method)."""
    certs_dir = str(PROJECT_DIR / "certs")

    if choice == 1:
        # Self-signed
        print("\n  Generating self-signed certificate...")
        try:
            import cert_manager
            cert_path, key_path = cert_manager.generate_self_signed_cert(
                hostname, certs_dir, validity_days=365
            )
            print(f"  Certificate: {cert_path}")
            print(f"  Private key: {key_path}")
            print("  (Browsers will show a security warning until trusted)")
            return cert_path, key_path, "selfsigned"
        except Exception as e:
            print(f"  ERROR: Failed to generate certificate: {e}")
            print("  Falling back to manual configuration.")
            return _setup_ssl(3, hostname, existing_config)

    elif choice == 2:
        # Let's Encrypt
        print()
        email = _prompt_input("Enter email for Let's Encrypt notifications")
        print(f"\n  Requesting certificate for {hostname}...")
        print("  (This requires port 80 to be accessible from the internet)\n")

        try:
            import cert_manager
            success, message = cert_manager.request_letsencrypt_cert(hostname, email)
            if success:
                cert_path, key_path = cert_manager.get_letsencrypt_cert_paths(hostname)
                cert_manager.install_renewal_hook("portal")
                print(f"  Success! Certificate issued.")
                print(f"  Certificate: {cert_path}")
                print(f"  Auto-renewal hook installed.")
                return cert_path, key_path, "letsencrypt"
            else:
                print(f"  ERROR: {message}")
                print("  Would you like to try a different method?")
                retry = _prompt_choice(
                    "Select alternative:",
                    ["Self-signed", "Custom certificate", "Exit setup"],
                )
                if retry == 1:
                    return _setup_ssl(1, hostname, existing_config)
                elif retry == 2:
                    return _setup_ssl(3, hostname, existing_config)
                else:
                    print("  Setup cancelled.")
                    sys.exit(1)
        except ImportError:
            print("  ERROR: cryptography library not installed.")
            print("  Install with: pip install cryptography")
            return _setup_ssl(3, hostname, existing_config)

    else:
        # Custom
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
            print(f"  WARNING: Certificate file not found: {cert_path}")
        if not Path(key_path).exists():
            print(f"  WARNING: Key file not found: {key_path}")
        else:
            # Validate the pair if both exist
            try:
                import cert_manager
                cert_data = Path(cert_path).read_bytes()
                key_data = Path(key_path).read_bytes()
                is_valid, error = cert_manager.validate_cert_key_pair(cert_data, key_data)
                if is_valid:
                    print("  Certificate and key validated successfully.")
                else:
                    print(f"  WARNING: {error}")
            except Exception:
                pass

        return cert_path, key_path, "custom"


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
        "",
        "# TLS Certificate",
        f"SSL_CERT={config.get('SSL_CERT', '')}",
        f"SSL_KEY={config.get('SSL_KEY', '')}",
        f"CERT_METHOD={config.get('CERT_METHOD', '')}",
    ]

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
    lines.append("")

    env_path.write_text("\n".join(lines))


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
    """Set up the initial admin user."""
    db_path = PROJECT_DIR / "portal.db"

    if db_path.exists():
        # Check if admin exists by trying to query
        print("  Database exists. Checking for admin user...")
        result = subprocess.run(
            [venv_python, str(PROJECT_DIR / "server.py"), "list-users"],
            capture_output=True, text=True, cwd=str(PROJECT_DIR),
        )
        if "admin" in result.stdout.lower():
            print("  Admin user already exists.")
            return

    print("  Creating admin user...")
    result = subprocess.run(
        [venv_python, str(PROJECT_DIR / "server.py"), "init"],
        capture_output=True, text=True, cwd=str(PROJECT_DIR),
    )
    if result.returncode == 0:
        print(result.stdout.strip())
    else:
        # init command may print to stderr
        output = result.stdout.strip() or result.stderr.strip()
        if "already exists" in output.lower():
            print("  Admin user already exists.")
        else:
            print(f"  {output}")


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

    # Check if running as root
    if os.geteuid() != 0:
        print("  Not running as root. To install the service manually:")
        print(f"    sudo cp {local_service} /etc/systemd/system/")
        print("    sudo systemctl daemon-reload")
        print("    sudo systemctl enable portal")
        print("    sudo systemctl start portal")
        return

    install = _prompt_yes_no("Install systemd service and enable?", default_yes=True)
    if not install:
        print("  Skipped. Install manually with:")
        print(f"    sudo cp {local_service} /etc/systemd/system/")
        print("    sudo systemctl daemon-reload && sudo systemctl enable portal")
        return

    # Copy to systemd
    target = Path("/etc/systemd/system/portal.service")
    shutil.copy2(local_service, target)
    print(f"  Installed to: {target}")

    # Daemon reload
    subprocess.run(["systemctl", "daemon-reload"], capture_output=True)
    print("  systemd reloaded.")

    # Enable
    subprocess.run(["systemctl", "enable", "portal"], capture_output=True)
    print("  Service enabled (will start on boot).")

    start = _prompt_yes_no("Start the portal service now?", default_yes=True)
    if start:
        result = subprocess.run(
            ["systemctl", "restart", "portal"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print("  Portal service started!")
        else:
            print(f"  WARNING: Failed to start: {result.stderr.strip()}")
            print("  Check logs with: sudo journalctl -u portal -f")


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
    if port == "443":
        print(f"  Open in browser: https://{hostname}")
    else:
        print(f"  Open in browser: https://{hostname}:{port}")
    print()


if __name__ == "__main__":
    run_setup_wizard()
