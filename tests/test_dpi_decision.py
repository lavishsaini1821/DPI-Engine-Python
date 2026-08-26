from scapy.all import IP, TCP
from src.dpi_engine import DPIEngine

# Create the DPI Engine.
engine = DPIEngine()

# Create a normal Scapy packet.
normal_packet = (
    IP(
        src="192.168.1.10",
        dst="8.8.8.8"
    )
    / TCP(
        sport=5000,
        dport=443
    )
)

# Create a Scapy packet from a blocked source IP.
blocked_packet = (
    IP(
        src="10.0.0.50",
        dst="8.8.8.8"
    )
    / TCP(
        sport=5001,
        dport=443
    )
)

# Process both packets through the DPI Engine.
parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets(
        [normal_packet, blocked_packet]
    )
)

print("Packet Decisions:")

for decision in decisions:
    print(decision)


# The order matters: the normal packet must be forwarded and the
# packet from the blocked source IP must be dropped. Comparing the
# whole list also catches a loop that evaluates only one packet.
assert decisions == ["FORWARD", "DROP"]
assert len(forwarded_packets) == 1
assert forwarded_packets[0] is normal_packet