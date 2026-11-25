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

    # Reverse proxies whose CF-Connecting-IP / X-Forwarded-For headers are
    # believed. Cloudflare's published ranges are always trusted; list extra
    # proxies here as comma-separated IPs/CIDRs (including 127.0.0.1,::1 for
    # a reverse proxy or cloudflared on this host). Requests arriving
    # from any other peer are attributed to the peer address itself, so a
    # client connecting straight to the origin cannot spoof its IP.
    TRUSTED_PROXIES: str = os.getenv("TRUSTED_PROXIES", "")

    # Addresses and CIDR networks that no automatic block may ever cover
    # (comma separated). Works without the database, so it still protects an
    # admin who is locked out. Nothing broader than /8 (IPv4) or /16 (IPv6)
    # is accepted. Loopback, this host's own addresses, trusted proxies and
    # Cloudflare are always exempt without being listed.
    NEVER_BAN_CIDRS: str = os.getenv("NEVER_BAN_CIDRS", "")

    # Destinations a webhook with allow_private may reach although a service the portal runs (MediaMTX,
    # the search backend, any managed service) listens there: host:port entries, IP addresses only (an
    # IPv6 address in brackets), comma or space separated. Empty by default: such a service is refused.
    # The portal's own listening ports are refused whatever is listed.
    WEBHOOK_LOCAL_ALLOW: str = os.getenv("WEBHOOK_LOCAL_ALLOW", "")

    # Opt-in: temporarily block clients that probe for files the portal never
    # serves (.env, .git/config, *.php, ...) after this many hits. 0 (the
    # default) leaves it off. Blocks are per IP, so a shared NAT is blocked
    # as a whole.
    PROBE_BLOCK_STRIKES: int = int(os.getenv("PROBE_BLOCK_STRIKES", "0"))
    PROBE_BLOCK_SECONDS: int = int(os.getenv("PROBE_BLOCK_SECONDS", "3600"))

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

    # Local staging folder for VOD chunks that are waiting to be uploaded.
    # Must survive a restart, so it is not under /tmp. A relative value is
    # resolved against the project directory. A folder that is not safe to use
    # (see vod_staging.dangerous_reason) is refused at start and the default
    # below is used instead; the server then updates VOD_TEMP_DIR to match.
    VOD_TEMP_DIR_DEFAULT: str = os.path.abspath(os.path.join(
        str(Path(__file__).parent), "data", "vod_tmp",
    ))
    VOD_TEMP_DIR: str = os.path.abspath(os.path.join(
        str(Path(__file__).parent),
        os.getenv("VOD_TEMP_DIR", "") or os.path.join("data", "vod_tmp"),
    ))

    # Cache of remuxed MP4 copies that the browser plays (My VODs, Play). Beside the staging folder,
    # never under /tmp; a folder that is not safe to use is refused (see vod_play.refusal_reason) and
    # playback is off until it is fixed. Its size cap is the setting vod_play_cache_mb.
    VOD_PLAY_CACHE_DIR: str = os.path.abspath(os.path.join(
        str(Path(__file__).parent),
        os.getenv("VOD_PLAY_CACHE_DIR", "") or os.path.join("data", "vod_play_cache"),
    ))

    # Run each local web-terminal shell in its own systemd scope, so tmux /
    # screen sessions started from it survive a portal restart.
    TERMINAL_OWN_SCOPE: bool = os.getenv("TERMINAL_OWN_SCOPE", "true").lower() == "true"

    # Vulnerability Scanner Settings
    NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")
    NMAP_PATH: str = os.getenv("NMAP_PATH", "/usr/bin/nmap")
    CVE_CACHE_TTL: int = int(os.getenv("CVE_CACHE_TTL", "3600"))  # 1 hour default
    VULN_SCAN_TIMEOUT: int = int(os.getenv("VULN_SCAN_TIMEOUT", "300"))  # 5 minutes

    # Public base URL used in announcements (watch links): "https://host[:port]", no path.
    # Empty: https:// plus HOSTNAME. Never taken from a request's Host header.
    PUBLIC_BASE_URL: str = os.getenv("PUBLIC_BASE_URL", "")

    # Stream hostname (for direct RTMP/RTMPS, bypasses CDN)
    STREAM_HOSTNAME: str = os.getenv("STREAM_HOSTNAME", os.getenv("HOSTNAME", "localhost"))

    # RTMP Plain (standard, non-TLS) ingress
    RTMP_PLAIN_ENABLED: bool = os.getenv("RTMP_PLAIN_ENABLED", "false").lower() == "true"
    RTMP_PLAIN_PORT: int = int(os.getenv("RTMP_PLAIN_PORT", "1935"))
    RTMP_TOKEN_EXPIRY_MINUTES: int = int(os.getenv("RTMP_TOKEN_EXPIRY_MINUTES", "15"))
    RTMP_TOKEN_GRACE_SECONDS: int = int(os.getenv("RTMP_TOKEN_GRACE_SECONDS", "300"))

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

    # Staged-instance test mode (tools/stage_smoke.py). For testing only: the
    # server skips every side effect on the host (managed-service autostart,
    # outgoing webhooks, game-server and update work, MediaMTX polling) so a
    # copy of the data can be run safely. Only the exact value "1" enables it,
    # and validate() refuses it on a non-loopback address or on port 443.
    STAGE_MODE: bool = os.getenv("PORTAL_STAGE_MODE", "") == "1"

    @classmethod
    def validate(cls) -> list[str]:
        """Validate configuration and return list of errors."""
        errors = []

        if cls.STAGE_MODE and (
            cls.HOST not in ("127.0.0.1", "::1", "localhost") or cls.PORT in (80, 443)
        ):
            errors.append(
                "PORTAL_STAGE_MODE=1 is for testing only: it needs HOST=127.0.0.1 "
                "and a port other than 80/443. Remove it from the production .env"
            )

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


# Shell whitelist for SSH and terminal connections (shared across server + plugins)
ALLOWED_SHELLS = {
    "/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh",
    "/usr/bin/fish", "/usr/bin/zsh", "/bin/zsh",
}
