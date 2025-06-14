from scapy.all import sniff, IP, TCP, UDP
import asyncio
import time

def extract_flow(pkt):
    if IP in pkt:
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'OTHER'
        return {
            'src_ip': pkt[IP].src,
            'dst_ip': pkt[IP].dst,
            'protocol': proto,
            'timestamp': time.time(),
            'packet_size': len(pkt)
        }
    return None

def packet_handler(flow_builder, signature_engine, alert_engine):
    loop = asyncio.get_event_loop()

    def handle(pkt):
        flow = extract_flow(pkt)
        if not flow:
            return

        flow_builder.update_flow(flow)
        signature_engine.check_rules(flow)

        flow_key = (flow["src_ip"], flow["dst_ip"])
        asyncio.run_coroutine_threadsafe(
            alert_engine.enrich_and_alert(flow_key, flow),
            loop
        )

    return handle

def start_sniffing(flow_builder, signature_engine, alert_engine):
    print("[*] Starting packet capture...")
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    sniff(
        prn=packet_handler(flow_builder, signature_engine, alert_engine),
        store=0,
        filter="ip"
    )
