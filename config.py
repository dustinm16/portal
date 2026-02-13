"""Configuration management for Open Relay Portal."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
# override=True ensures .env values take precedence over system env vars
# (critical for HOSTNAME which is a standard Linux shell variable)
load_dotenv(Path(__file__).parent / ".env", override=True)


class Config:
    """Application configuration loaded from environment variables."""

    # JWT Settings
    JWT_SECRET: str = os.getenv("JWT_SECRET", "")
    JWT_ALGORITHM: str = "HS256"
    TOKEN_EXPIRY_HOURS: int = int(os.getenv("TOKEN_EXPIRY_HOURS", "720"))

    # Server Settings
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "443"))
    HOSTNAME: str = os.getenv("HOSTNAME", "localhost")

    # SSL Certificate Paths
    SSL_CERT: str = os.getenv(
        "SSL_CERT", f"/etc/letsencrypt/live/{os.getenv('HOSTNAME', 'localhost')}/fullchain.pem"
    )
    SSL_KEY: str = os.getenv(
        "SSL_KEY", f"/etc/letsencrypt/live/{os.getenv('HOSTNAME', 'localhost')}/privkey.pem"
    )

    # Database
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH", str(Path(__file__).parent / "portal.db")
    )

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

    # Session Cookie Settings
    SESSION_COOKIE_NAME: str = os.getenv("SESSION_COOKIE_NAME", "portal_session")
    SESSION_COOKIE_MAX_AGE: int = int(os.getenv("SESSION_COOKIE_MAX_AGE", "86400"))  # 24 hours
    SESSION_COOKIE_SECURE: bool = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")

    # TLS Settings
    TLS_MIN_VERSION: str = "TLSv1.2"

    # Shodan API Settings
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")

    # Metrics Settings
    METRICS_ENABLED: bool = os.getenv("METRICS_ENABLED", "true").lower() == "true"
    METRICS_RETENTION_HOURS: int = int(os.getenv("METRICS_RETENTION_HOURS", "24"))

    # Two-Factor Authentication Settings
    TOTP_ISSUER: str = os.getenv("TOTP_ISSUER", "Open Relay Portal")

    # Session Recording Settings
    RECORDINGS_DIR: str = os.getenv(
        "RECORDINGS_DIR", str(Path(__file__).parent / "recordings")
    )
    RECORDING_ENABLED: bool = os.getenv("RECORDING_ENABLED", "true").lower() == "true"

    # Vulnerability Scanner Settings
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NMAP_PATH: str = os.getenv("NMAP_PATH", "/usr/bin/nmap")
    CVE_CACHE_TTL: int = int(os.getenv("CVE_CACHE_TTL", "3600"))  # 1 hour default
    VULN_SCAN_TIMEOUT: int = int(os.getenv("VULN_SCAN_TIMEOUT", "300"))  # 5 minutes

    # Stream hostname (for direct RTMP/RTMPS, bypasses CDN)
    STREAM_HOSTNAME: str = os.getenv("STREAM_HOSTNAME", os.getenv("HOSTNAME", "localhost"))

    # RTMP Plain (standard, non-TLS) ingress
    RTMP_PLAIN_ENABLED: bool = os.getenv("RTMP_PLAIN_ENABLED", "false").lower() == "true"
    RTMP_PLAIN_PORT: int = int(os.getenv("RTMP_PLAIN_PORT", "1935"))
    RTMP_TOKEN_EXPIRY_MINUTES: int = int(os.getenv("RTMP_TOKEN_EXPIRY_MINUTES", "15"))
    RTMP_TOKEN_GRACE_SECONDS: int = int(os.getenv("RTMP_TOKEN_GRACE_SECONDS", "30"))

    # Certificate Management
    CERT_METHOD: str = os.getenv("CERT_METHOD", "")  # letsencrypt, selfsigned, custom
    CERTS_DIR: str = str(Path(__file__).parent / "certs")

    # File Manager
    FILE_MANAGER_ROOT: str = os.getenv("FILE_MANAGER_ROOT", "/")
    FILE_MANAGER_MAX_UPLOAD: int = int(os.getenv("FILE_MANAGER_MAX_UPLOAD_MB", "100")) * 1024 * 1024

    # SEO / Search Engine Verification
    GOOGLE_SITE_VERIFICATION: str = os.getenv("GOOGLE_SITE_VERIFICATION", "")  # meta tag content
    GOOGLE_VERIFICATION_FILE: str = os.getenv("GOOGLE_VERIFICATION_FILE", "")  # filename ID (e.g. 46ea35705e711807)
    BING_SITE_VERIFICATION: str = os.getenv("BING_SITE_VERIFICATION", "")  # Bing Webmaster Tools verification
    YANDEX_SITE_VERIFICATION: str = os.getenv("YANDEX_SITE_VERIFICATION", "")  # Yandex Webmaster verification
    INDEXNOW_API_KEY: str = os.getenv("INDEXNOW_API_KEY", "")  # IndexNow instant indexing (Bing, Yandex, Seznam, Naver)

    # Voice Chat (WebRTC ICE servers)
    STUN_SERVER: str = os.getenv("STUN_SERVER", "stun:stun.l.google.com:19302")
    TURN_SERVER: str = os.getenv("TURN_SERVER", "")
    TURN_USERNAME: str = os.getenv("TURN_USERNAME", "")
    TURN_PASSWORD: str = os.getenv("TURN_PASSWORD", "")

    @classmethod
    def validate(cls) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not cls.JWT_SECRET or cls.JWT_SECRET == "change_me_to_a_random_64_char_hex_string":
            errors.append("JWT_SECRET must be set to a secure random value")

        if cls.JWT_SECRET and len(cls.JWT_SECRET) < 32:
            errors.append("JWT_SECRET should be at least 32 characters")

        if not Path(cls.SSL_CERT).exists():
            errors.append(f"SSL certificate not found: {cls.SSL_CERT}")

        if not Path(cls.SSL_KEY).exists():
            errors.append(f"SSL private key not found: {cls.SSL_KEY}")

        return errors

    @classmethod
    def validate_or_warn(cls) -> bool:
        """Validate and print warnings. Returns True if critical errors exist."""
        errors = cls.validate()
        if not errors:
            return False

        print()
        print("=" * 60)
        print("  CONFIGURATION ERRORS — Server cannot start")
        print("=" * 60)
        for error in errors:
            print(f"  [!] {error}")
        print()

        # Check if .env exists
        env_path = Path(__file__).parent / ".env"
        if not env_path.exists():
            print("  No .env file found. Run the setup wizard:")
            print("    sudo python server.py setup")
        else:
            # Give targeted advice based on which errors
            ssl_errors = [e for e in errors if "SSL" in e]
            if ssl_errors:
                print("  TLS certificate issue detected.")
                print("  This is the most common cause of 'page took too long to respond'.")
                print()
                print("  Quick fix — generate a self-signed certificate:")
                print(f"    cd {Path(__file__).parent}")
                print("    python -c \"import cert_manager; print(cert_manager.generate_self_signed_cert('" + cls.HOSTNAME + "', 'certs'))\"")
                print("    # Then update SSL_CERT and SSL_KEY in .env")
                print()
                print("  Or re-run the setup wizard:")
                print("    sudo python server.py setup")

        print("=" * 60)
        print()
        return True
