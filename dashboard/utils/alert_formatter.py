def format_alert_payload(alert_type, description, flow, timestamp, severity):
    return {
        "type": alert_type,
        "description": description,
        "src_ip": flow.get("src_ip"),
        "dst_ip": flow.get("dst_ip"),
        "protocol": flow.get("protocol"),
        "timestamp": timestamp,
        "severity": severity
    }
    
