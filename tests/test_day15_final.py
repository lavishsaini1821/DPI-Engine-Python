from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine

# Load the real PCAP file.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Create the complete DPI Engine.
engine = DPIEngine()

# Process all packets through the complete pipeline.
parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets(packets)
)

print("========== DAY 15 FINAL VERIFICATION ==========")

# Basic packet verification.
print("\nPacket Processing:")
print("Total packets:", len(packets))
print("Parsed packets:", len(parsed_packets))

# Protocol verification.
print("\nProtocol Statistics:")
for protocol, count in protocol_statistics.items():
    print(f"{protocol}: {count}")

# Flow verification.
print("\nFlow Tracking:")
print(
    "Total flows:",
    engine.connection_tracker.get_flow_count()
)

# SNI verification.
sni_flows = [
    flow
    for flow in engine.connection_tracker.flows.values()
    if flow.sni
]

print("Flows with SNI:", len(sni_flows))

# Display classified applications.
print("\nClassified SNI Flows:")

for flow in sni_flows:
    print(
        f"{flow.sni} -> "
        f"{flow.app_type.value} -> "
        f"{'DROP' if flow.blocked else 'FORWARD'}"
    )

# Enforcement verification.
forward_count = decisions.count("FORWARD")
drop_count = decisions.count("DROP")

print("\nEnforcement:")
print("FORWARD:", forward_count)
print("DROP:", drop_count)

# Final verification checks.
print("\nVerification:")

print(
    "Packet parsing:",
    "PASS" if len(packets) == len(parsed_packets)
    else "FAIL"
)

print(
    "Flow tracking:",
    "PASS"
    if engine.connection_tracker.get_flow_count() > 0
    else "FAIL"
)

print(
    "SNI extraction:",
    "PASS"
    if len(sni_flows) > 0
    else "FAIL"
)

print(
    "Enforcement:",
    "PASS"
    if len(decisions) == len(packets)
    else "FAIL"
)