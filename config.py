"""Configuration management for Portal Gateway."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(Path(__file__).parent / ".env")


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

    @classmethod
    def validate(cls) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if not cls.JWT_SECRET or cls.JWT_SECRET == "change_me_to_a_random_64_char_hex_string":
            errors.append("JWT_SECRET must be set to a secure random value")

        if len(cls.JWT_SECRET) < 32:
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
        for error in errors:
            print(f"[CONFIG WARNING] {error}")
        return len(errors) > 0
