from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine

# Load the real test PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Create the real DPI Engine.
engine = DPIEngine()

# Process all packets through the complete DPI pipeline.
parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets(packets)
)

# Display basic processing information.
print("Total packets:", len(packets))
print("Parsed packets:", len(parsed_packets))

# Display protocol statistics.
print("\nProtocol Statistics:")

for protocol, count in protocol_statistics.items():
    print(f"{protocol}: {count}")


# Display all flows created by the DPI Engine.
print("\nTracked Flows:")
print("Total flows:", engine.connection_tracker.get_flow_count())

# Display flows for which SNI was detected.
print("\nFlows with SNI:")

sni_flow_count = 0

for flow in engine.connection_tracker.flows.values():

    if flow.sni:
        sni_flow_count += 1

        print(
            f"SNI: {flow.sni} | "
            f"Application: {flow.app_type.value} | "
            f"Blocked: {flow.blocked}"
        )


print("\nTotal SNI Flows:", sni_flow_count)

# Display the number of DROP and FORWARD decisions.
drop_count = decisions.count("DROP")
forward_count = decisions.count("FORWARD")

print("\nEnforcement Statistics:")
print("FORWARD:", forward_count)
print("DROP:", drop_count)