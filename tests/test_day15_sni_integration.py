from src.dpi_engine import DPIEngine

# Create the DPI Engine.
engine = DPIEngine()

# Create a fake TLS ClientHello payload.
# This is used only to verify the SNI integration path.
class TestSNIExtractor:
    def extract(self, payload):
        return "phishing.com"

# Replace the real extractor with our controlled test extractor.
engine.sni_extractor = TestSNIExtractor()

# Create a test packet using Scapy.
from scapy.all import IP, TCP

packet = (
    IP(
        src="192.168.1.20",
        dst="8.8.8.8"
    )
    / TCP(
        sport=5000,
        dport=443
    )
)

# Process the packet through the actual DPI Engine.
parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets([packet])
)

# Get the only tracked flow.
flow = next(iter(engine.connection_tracker.flows.values()))

print("SNI:", flow.sni)
print("Application:", flow.app_type.value)
print("Blocked:", flow.blocked)
print("Decision:", decisions[0])