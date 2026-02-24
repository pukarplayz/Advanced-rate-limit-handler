import httpx
import json
import logging
from typing import Dict, Any, Optional
from ..models.rate_limit import AbuseAlert
from ..core.config import settings

logger = logging.getLogger(__name__)


class WebhookService:
    """Service for sending webhook alerts on abuse detection"""

    def __init__(self):
        self.webhook_url = settings.webhook_url
        self.timeout = settings.webhook_timeout

    async def send_alert(self, alert: AbuseAlert) -> bool:
        """Send abuse alert via webhook"""
        if not self.webhook_url:
            logger.warning("No webhook URL configured, skipping alert")
            return False

        try:
            payload = {
                "timestamp": alert.metadata.get("timestamp", None),
                "alert_type": alert.alert_type,
                "identifier": alert.identifier,
                "threshold_breached": alert.threshold_breached,
                "current_count": alert.current_count,
                "time_window": alert.time_window,
                "metadata": alert.metadata
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.webhook_url,
                    json=payload,
                    headers={"Content-Type": "application/json"}
                )

                if response.status_code == 200:
                    logger.info(f"Webhook alert sent successfully for {alert.identifier}")
                    return True
                else:
                    logger.error(
                        f"Webhook failed with status {response.status_code}: {response.text}"
                    )
                    return False

        except Exception as e:
            logger.error(f"Failed to send webhook alert: {e}")
            return False

    async def alert_rate_limit_exceeded(
        self,
        identifier: str,
        limit: int,
        current_count: int,
        time_window: int,
        route: str = ""
    ):
        """Send alert for rate limit violations"""
        alert = AbuseAlert(
            alert_type="rate_limit_exceeded",
            identifier=identifier,
            threshold_breached=limit,
            current_count=current_count,
            time_window=time_window,
            metadata={
                "route": route,
                "violation_count": current_count - limit
            }
        )
        await self.send_alert(alert)

    async def alert_suspicious_activity(
        self,
        identifier: str,
        activity_type: str,
        severity: str = "medium",
        metadata: Dict[str, Any] = None
    ):
        """Send alert for suspicious activity patterns"""
        alert = AbuseAlert(
            alert_type="suspicious_activity",
            identifier=identifier,
            threshold_breached=0,  # Not applicable
            current_count=0,  # Not applicable
            time_window=0,  # Not applicable
            metadata={
                "activity_type": activity_type,
                "severity": severity,
                **(metadata or {})
            }
        )
        await self.send_alert(alert)

    async def alert_system_health(
        self,
        component: str,
        status: str,
        details: Dict[str, Any] = None
    ):
        """Send alert for system health issues"""
        alert = AbuseAlert(
            alert_type="system_health",
            identifier=f"system:{component}",
            threshold_breached=0,
            current_count=0,
            time_window=0,
            metadata={
                "component": component,
                "status": status,
                **(details or {})
            }
        )
        await self.send_alert(alert)