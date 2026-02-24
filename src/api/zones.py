from fastapi import APIRouter, Depends, HTTPException, Header
from typing import List, Optional
from ..models.rate_limit import Zone, ZoneConfig
from ..services.zone_service import ZoneService
from pydantic import BaseModel

class CreateZoneRequest(BaseModel):
    name: str
    description: Optional[str] = None
    owner: str = "default"

router = APIRouter(prefix="/zones", tags=["zones"])


# Dependency to get zone service
def get_zone_service():
    return ZoneService()


@router.post("/", response_model=Zone)
async def create_zone(
    request: CreateZoneRequest,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Create a new security zone"""
    try:
        zone = await zone_service.create_zone(request.name, request.owner, request.description)
        return zone
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create zone: {str(e)}")


@router.get("/", response_model=List[Zone])
async def list_zones(
    owner: Optional[str] = None,
    status: str = "active",
    zone_service: ZoneService = Depends(get_zone_service)
):
    """List zones with optional filtering"""
    try:
        zones = await zone_service.list_zones(owner, status)
        return zones
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list zones: {str(e)}")


@router.get("/{zone_id}", response_model=Zone)
async def get_zone(
    zone_id: str,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Get zone by ID"""
    zone = await zone_service.get_zone(zone_id)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    return zone


@router.put("/{zone_id}", response_model=Zone)
async def update_zone(
    zone_id: str,
    name: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Update zone information"""
    updates = {}
    if name is not None:
        updates["name"] = name
    if description is not None:
        updates["description"] = description
    if status is not None:
        updates["status"] = status

    zone = await zone_service.update_zone(zone_id, updates)
    if not zone:
        raise HTTPException(status_code=404, detail="Zone not found")
    return zone


@router.delete("/{zone_id}")
async def delete_zone(
    zone_id: str,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Delete a zone"""
    success = await zone_service.delete_zone(zone_id)
    if not success:
        raise HTTPException(status_code=404, detail="Zone not found")
    return {"message": "Zone deleted successfully"}


@router.get("/{zone_id}/config", response_model=ZoneConfig)
async def get_zone_config(
    zone_id: str,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Get zone configuration"""
    config = await zone_service.get_zone_config(zone_id)
    return config


@router.put("/{zone_id}/config", response_model=ZoneConfig)
async def update_zone_config(
    zone_id: str,
    config_updates: dict,
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Update zone configuration (live updates)"""
    try:
        config = await zone_service.update_zone_config(zone_id, config_updates)
        return config
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")


@router.get("/{zone_id}/analytics")
async def get_zone_analytics(
    zone_id: str,
    time_range: str = "24h",
    zone_service: ZoneService = Depends(get_zone_service)
):
    """Get zone analytics"""
    analytics = await zone_service.get_zone_analytics(zone_id, time_range)
    return analytics


# Zone identification middleware helper
async def get_current_zone(
    x_zone_key: str = Header(None, alias="X-Zone-Key"),
    zone_service: ZoneService = Depends(get_zone_service)
) -> Optional[Zone]:
    """Get current zone from request header"""
    if not x_zone_key:
        return None

    zone = await zone_service.get_zone_by_key(x_zone_key)
    if not zone or zone.status != "active":
        return None

    return zone