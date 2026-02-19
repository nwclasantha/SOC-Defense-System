import os
import logging
from typing import Optional, Dict, Any

# Try to import geoip2, set flag if available
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Enrichment Services
class GeoIPEnricher:
    """Enrich IP addresses with geographical information."""

    def __init__(self, database_path: Optional[str] = None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reader = None

        if database_path and database_path != '' and os.path.exists(database_path) and GEOIP_AVAILABLE:
            try:
                self.reader = geoip2.database.Reader(database_path)
                self.logger.info("GeoIP database loaded successfully")
            except Exception as e:
                self.logger.warning(f"Failed to load GeoIP database: {e}")
        elif not GEOIP_AVAILABLE:
            self.logger.warning("geoip2 module not installed. GeoIP enrichment will be disabled.")

    def enrich(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geographical information for an IP address."""
        if not self.reader:
            return None

        try:
            response = self.reader.city(ip_address)

            return {
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'network': response.traits.network.with_prefixlen if hasattr(response.traits, 'network') else None
            }

        except Exception as e:
            self.logger.debug(f"GeoIP lookup failed for {ip_address}: {e}")
            return None

    def __del__(self):
        """Clean up resources."""
        if self.reader:
            self.reader.close()
