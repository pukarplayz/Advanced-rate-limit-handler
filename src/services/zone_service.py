import secrets
import time
import json
from typing import Dict, Any, Optional, List
from ..core.redis_client import redis_client
from ..models.rate_limit import Zone, ZoneConfig, SecurityRule, ZoneAnalytics
import logging

logger = logging.getLogger(__name__)


class ZoneService:
    """Multi-tenant zone management service"""

    def __init__(self):
        self.redis = redis_client

    async def create_zone(self, name: str, owner: str, description: str = None) -> Zone:
        """Create a new security zone"""
        zone_id = f"zone_{secrets.token_hex(8)}"
        api_key = f"sk_live_{secrets.token_hex(16)}"

        zone = Zone(
            id=zone_id,
            name=name,
            owner=owner,
            api_key=api_key,
            created_at=int(time.time()),
            description=description
        )

        # Store zone
        try:
            client = await self.redis.connect()
            if client:
                await client.setex(f"zone:{zone_id}", 86400 * 365, zone.json())  # 1 year TTL
                await client.setex(f"zone_key:{api_key}", 86400 * 365, zone_id)

                # Create default configuration
                default_config = ZoneConfig(
                    zone_id=zone_id,
                    updated_at=int(time.time())
                )
                await client.setex(f"zone_config:{zone_id}", 86400 * 365, default_config.json())

                logger.info(f"Created zone {zone_id} for owner {owner}")
        except Exception as e:
            logger.error(f"Failed to create zone: {e}")
            raise

        return zone

    async def get_zone(self, zone_id: str) -> Optional[Zone]:
        """Get zone by ID"""
        try:
            client = await self.redis.connect()
            if client:
                zone_data = await client.get(f"zone:{zone_id}")
                if zone_data:
                    return Zone.parse_raw(zone_data)
        except Exception as e:
            logger.error(f"Failed to get zone {zone_id}: {e}")

        return None

    async def get_zone_by_key(self, api_key: str) -> Optional[Zone]:
        """Get zone by API key"""
        try:
            client = await self.redis.connect()
            if client:
                zone_id = await client.get(f"zone_key:{api_key}")
                if zone_id:
                    return await self.get_zone(zone_id)
        except Exception as e:
            logger.error(f"Failed to get zone by key: {e}")

        return None

    async def update_zone(self, zone_id: str, updates: Dict[str, Any]) -> Optional[Zone]:
        """Update zone information"""
        zone = await self.get_zone(zone_id)
        if not zone:
            return None

        # Update allowed fields
        allowed_updates = ['name', 'description', 'status']
        for key, value in updates.items():
            if key in allowed_updates:
                setattr(zone, key, value)

        # Save updated zone
        try:
            client = await self.redis.connect()
            if client:
                await client.setex(f"zone:{zone_id}", 86400 * 365, zone.json())
                logger.info(f"Updated zone {zone_id}")
        except Exception as e:
            logger.error(f"Failed to update zone {zone_id}: {e}")
            raise

        return zone

    async def delete_zone(self, zone_id: str) -> bool:
        """Delete a zone (mark as deleted)"""
        zone = await self.get_zone(zone_id)
        if not zone:
            return False

        zone.status = "deleted"

        try:
            client = await self.redis.connect()
            if client:
                await client.setex(f"zone:{zone_id}", 86400 * 365, zone.json())
                logger.info(f"Deleted zone {zone_id}")
                return True
        except Exception as e:
            logger.error(f"Failed to delete zone {zone_id}: {e}")

        return False

    async def get_zone_config(self, zone_id: str) -> ZoneConfig:
        """Get zone configuration"""
        try:
            client = await self.redis.connect()
            if client:
                config_data = await client.get(f"zone_config:{zone_id}")
                if config_data:
                    return ZoneConfig.parse_raw(config_data)
        except Exception as e:
            logger.error(f"Failed to get zone config {zone_id}: {e}")

        # Return default config if not found
        return ZoneConfig(zone_id=zone_id, updated_at=int(time.time()))

    async def update_zone_config(self, zone_id: str, config_updates: Dict[str, Any]) -> ZoneConfig:
        """Update zone configuration with live updates"""
        current_config = await self.get_zone_config(zone_id)

        # Update configuration
        for section, updates in config_updates.items():
            if hasattr(current_config, section):
                current_section = getattr(current_config, section)
                if isinstance(current_section, dict):
                    current_section.update(updates)
                else:
                    setattr(current_config, section, updates)

        current_config.version += 1
        current_config.updated_at = int(time.time())

        # Save updated config
        try:
            client = await self.redis.connect()
            if client:
                await client.setex(f"zone_config:{zone_id}", 86400 * 365, current_config.json())
                # Invalidate any cached config
                await client.delete(f"zone_config_cache:{zone_id}")
                logger.info(f"Updated zone config {zone_id} to version {current_config.version}")
        except Exception as e:
            logger.error(f"Failed to update zone config {zone_id}: {e}")
            raise

        return current_config

    async def get_zone_analytics(self, zone_id: str, time_range: str = "24h") -> ZoneAnalytics:
        """Get zone analytics"""
        try:
            client = await self.redis.connect()
            if client:
                # Get analytics data from Redis (would be populated by middleware)
                analytics_key = f"zone_analytics:{zone_id}:{time_range}"
                analytics_data = await client.get(analytics_key)

                if analytics_data:
                    return ZoneAnalytics.parse_raw(analytics_data)
        except Exception as e:
            logger.error(f"Failed to get zone analytics {zone_id}: {e}")

        # Return empty analytics
        return ZoneAnalytics(zone_id=zone_id, time_range=time_range)

    async def list_zones(self, owner: str = None, status: str = "active") -> List[Zone]:
        """List zones with optional filtering"""
        zones = []
        try:
            client = await self.redis.connect()
            if client:
                # Get all zone keys (simplified - in production use SCAN)
                pattern = "zone:*"
                keys = await client.keys(pattern)

                for key in keys[:50]:  # Limit for performance
                    zone_data = await client.get(key)
                    if zone_data:
                        zone = Zone.parse_raw(zone_data)
                        if (not owner or zone.owner == owner) and zone.status == status:
                            zones.append(zone)
        except Exception as e:
            logger.error(f"Failed to list zones: {e}")

        return zones

    async def validate_zone_access(self, zone_id: str, api_key: str) -> bool:
        """Validate that API key has access to zone"""
        zone = await self.get_zone(zone_id)
        return zone and zone.api_key == api_key and zone.status == "active"