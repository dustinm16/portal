"""Shodan API Integration for Open Relay Portal."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
import aiohttp

logger = logging.getLogger("portal.shodan")


@dataclass
class PortInfo:
    """Information about an open port."""
    port: int
    protocol: str
    service: str
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    vulns: list[str] = field(default_factory=list)


@dataclass
class ShodanHostInfo:
    """Shodan host information."""
    ip: str
    hostnames: list[str]
    country: Optional[str]
    city: Optional[str]
    org: Optional[str]
    isp: Optional[str]
    asn: Optional[str]
    ports: list[PortInfo]
    vulns: list[str]
    last_update: Optional[datetime]
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "hostnames": self.hostnames,
            "country": self.country,
            "city": self.city,
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "vulns": p.vulns
                }
                for p in self.ports
            ],
            "vulns": self.vulns,
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "tags": self.tags,
            "risk_score": self.calculate_risk_score()
        }

    def calculate_risk_score(self) -> dict:
        """Calculate a risk score based on open ports and vulnerabilities."""
        score = 0
        risk_level = "low"
        factors = []

        # High-risk ports
        high_risk_ports = {21, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 6379, 27017}
        medium_risk_ports = {22, 80, 443, 8080, 8443}

        for port in self.ports:
            if port.port in high_risk_ports:
                score += 20
                factors.append(f"High-risk port {port.port} ({port.service})")
            elif port.port in medium_risk_ports:
                score += 5

        # Vulnerabilities
        critical_vulns = [v for v in self.vulns if 'CVE' in v]
        score += len(critical_vulns) * 25
        if critical_vulns:
            factors.append(f"{len(critical_vulns)} known vulnerabilities")

        # Determine risk level
        if score >= 75:
            risk_level = "critical"
        elif score >= 50:
            risk_level = "high"
        elif score >= 25:
            risk_level = "medium"

        return {
            "score": min(score, 100),
            "level": risk_level,
            "factors": factors
        }


class ShodanClient:
    """Async client for Shodan API."""

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._session: Optional[aiohttp.ClientSession] = None
        self._cache: dict[str, tuple[ShodanHostInfo, datetime]] = {}
        self._cache_ttl = 3600  # 1 hour cache

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=30)
            )
        return self._session

    async def close(self):
        """Close the HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()

    def set_api_key(self, api_key: str):
        """Set or update the API key."""
        self.api_key = api_key
        self._cache.clear()

    async def lookup_host(self, ip: str, use_cache: bool = True) -> Optional[ShodanHostInfo]:
        """Look up a host by IP address."""
        if not self.api_key:
            logger.warning("Shodan API key not configured")
            return None

        # Check cache
        if use_cache and ip in self._cache:
            cached, cached_time = self._cache[ip]
            if (datetime.now(timezone.utc) - cached_time).seconds < self._cache_ttl:
                logger.debug(f"Returning cached Shodan data for {ip}")
                return cached

        try:
            session = await self._get_session()
            url = f"{self.BASE_URL}/shodan/host/{ip}"
            params = {"key": self.api_key}

            async with session.get(url, params=params) as response:
                if response.status == 404:
                    logger.info(f"No Shodan data found for {ip}")
                    return None
                elif response.status == 401:
                    logger.error("Invalid Shodan API key")
                    return None
                elif response.status == 429:
                    logger.warning("Shodan API rate limit exceeded")
                    return None
                elif response.status != 200:
                    logger.error(f"Shodan API error: {response.status}")
                    return None

                data = await response.json()
                host_info = self._parse_host_data(data)

                # Cache the result
                if host_info:
                    self._cache[ip] = (host_info, datetime.now(timezone.utc))

                return host_info

        except asyncio.TimeoutError:
            logger.error(f"Timeout looking up {ip} in Shodan")
            return None
        except Exception as e:
            logger.error(f"Error looking up {ip} in Shodan: {e}")
            return None

    def _parse_host_data(self, data: dict) -> ShodanHostInfo:
        """Parse Shodan API response into ShodanHostInfo."""
        ports = []
        seen_ports = set()

        for service in data.get("data", []):
            port_num = service.get("port")
            if port_num in seen_ports:
                continue
            seen_ports.add(port_num)

            port_info = PortInfo(
                port=port_num,
                protocol=service.get("transport", "tcp"),
                service=service.get("_shodan", {}).get("module", "unknown"),
                product=service.get("product"),
                version=service.get("version"),
                banner=service.get("data", "")[:500] if service.get("data") else None,
                vulns=list(service.get("vulns", {}).keys()) if service.get("vulns") else []
            )
            ports.append(port_info)

        # Sort ports by number
        ports.sort(key=lambda p: p.port)

        # Collect all vulns
        all_vulns = set()
        for p in ports:
            all_vulns.update(p.vulns)
        all_vulns.update(data.get("vulns", []))

        last_update = None
        if data.get("last_update"):
            try:
                last_update = datetime.fromisoformat(data["last_update"].replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass

        return ShodanHostInfo(
            ip=data.get("ip_str", ""),
            hostnames=data.get("hostnames", []),
            country=data.get("country_name"),
            city=data.get("city"),
            org=data.get("org"),
            isp=data.get("isp"),
            asn=data.get("asn"),
            ports=ports,
            vulns=list(all_vulns),
            last_update=last_update,
            tags=data.get("tags", [])
        )

    async def get_api_info(self) -> Optional[dict]:
        """Get API key info (credits remaining, etc.)."""
        if not self.api_key:
            return None

        try:
            session = await self._get_session()
            url = f"{self.BASE_URL}/api-info"
            params = {"key": self.api_key}

            async with session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                return None

        except Exception as e:
            logger.error(f"Error getting Shodan API info: {e}")
            return None

    async def search(self, query: str, limit: int = 10) -> list[dict]:
        """Search Shodan for hosts matching a query."""
        if not self.api_key:
            return []

        try:
            session = await self._get_session()
            url = f"{self.BASE_URL}/shodan/host/search"
            params = {
                "key": self.api_key,
                "query": query,
                "page": 1
            }

            async with session.get(url, params=params) as response:
                if response.status != 200:
                    return []

                data = await response.json()
                results = []

                for match in data.get("matches", [])[:limit]:
                    results.append({
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "org": match.get("org"),
                        "hostnames": match.get("hostnames", []),
                        "product": match.get("product"),
                        "location": {
                            "country": match.get("location", {}).get("country_name"),
                            "city": match.get("location", {}).get("city")
                        }
                    })

                return results

        except Exception as e:
            logger.error(f"Error searching Shodan: {e}")
            return []


# Global Shodan client instance
shodan_client = ShodanClient()


async def init_shodan(api_key: Optional[str] = None):
    """Initialize the Shodan client with an API key."""
    if api_key:
        shodan_client.set_api_key(api_key)
        logger.info("Shodan client initialized")


async def shutdown_shodan():
    """Shutdown the Shodan client."""
    await shodan_client.close()
