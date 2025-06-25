def format_alert_payload(alert_type, description, flow, timestamp, severity="medium"):
    return {
        "type": alert_type,
        "description": description,
        "source_ip": flow.get("source_ip"),
        "destination_ip": flow.get("destination_ip"),
        "protocol": flow.get("protocol"),
        "timestamp": timestamp,
        "severity": severity
    }