import logging
from logger_config.logger import setup_log
setup_log() # Configure logging
from core.packet_sniffer import start_sniffing
from core.flow_builder import FlowBuilder
from core.signature_engine import SignatureEngine
from core.alert_engine import AlertEngine

def main():
    try:
        logging.info("🔧 Initializing modules...")
        flow_builder = FlowBuilder()
        signature_engine = SignatureEngine()
        alert_engine = AlertEngine(
            abuseipdb_key="YOUR_ABUSEIPDB_API_KEY",
            otx_key="YOUR_OTX_API_KEY",
            misp_url="https://your-misp-instance.com",
            misp_key="YOUR_MISP_API_KEY"
        )
        logging.info("🚀 Starting packet sniffing...")
        start_sniffing(flow_builder, signature_engine, alert_engine)

    except KeyboardInterrupt:
        logging.warning("🛑 Packet sniffing interrupted by user.")
    except Exception as e:
        logging.exception(f"❌ An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()  