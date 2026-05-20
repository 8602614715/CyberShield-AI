import logging

logging.basicConfig(level=logging.INFO)
alert_logger = logging.getLogger("cyberfraud.alerts")


def send_alert_notification(report_id: str, risk_level: str, details: str) -> None:
    if risk_level == "critical":
        alert_logger.warning(
            f"CRITICAL ALERT TRIGGERED for Report {report_id}\nDetails: {details}"
        )
