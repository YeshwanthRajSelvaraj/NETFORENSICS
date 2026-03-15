import os
import json
import logging
import httpx
from typing import Dict, Any

logger = logging.getLogger("nf-siem-forwarder")

# Example Configuration (in production, fetch per-tenant configs from PostgreSQL)
SPLUNK_HEC_URL = os.environ.get("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")

# Webhook configurations for Microsoft Sentinel / Custom SOC MS Teams channels
WEBHOOK_URL = os.environ.get("SOC_WEBHOOK_URL", "")


async def forward_to_splunk(alert: Dict[str, Any]):
    """
    HTTP Event Collector (HEC) Forwarder for Splunk Enterprise/Cloud.
    Transforms the internal NetForensics alert format into Splunk JSON.
    """
    if not SPLUNK_HEC_URL or not SPLUNK_HEC_TOKEN:
        return

    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "time": alert.get("timestamp", 0),  # Splunk requires epoch
        "host": alert.get("sensor_id", "nf-cluster"),
        "source": "netforensics-ai",
        "sourcetype": "_json",
        "event": {
            "tenant_id": alert.get("tenant_id"),
            "alert_id": alert.get("alert_id"),
            "severity": alert.get("severity"),
            "engine": alert.get("engine_name"),
            "mitre_tactics": alert.get("mitre_tactics", []),
            "description": alert.get("description", "")
        }
    }

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=5.0)
            if resp.status_code != 200:
                logger.error(f"Failed to forward to Splunk HEC: {resp.status_code} - {resp.text}")
            else:
                logger.info(f"Successfully forwarded Alert {alert['alert_id']} to Splunk HEC.")
    except Exception as e:
        logger.error(f"Splunk forwarding error: {e}")


async def trigger_webhook(alert: Dict[str, Any]):
    """Standard generic webhook for Slack / Microsoft Teams / Custom integration."""
    if not WEBHOOK_URL:
        return

    # Filter to only trigger on critical alerts to prevent alert fatigue
    if alert.get("severity", "").upper() not in ["CRITICAL", "HIGH"]:
        return

    payload = {
        "text": f"🚨 *NetForensics [{alert.get('severity')}]*\n_{alert.get('title')}_\n\n{alert.get('description')}\n*MITRE:* {', '.join(alert.get('mitre_tactics', []))}"
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(WEBHOOK_URL, json=payload, timeout=3.0)
            logger.info(f"Fired critical webhook for Alert {alert['alert_id']}.")
    except Exception as e:
        logger.error(f"Webhook error: {e}")
