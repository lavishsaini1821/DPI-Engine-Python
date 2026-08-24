from scapy.all import rdpcap, wrpcap
from src.dpi_engine import DPIEngine

INPUT_PCAP = "input/test_dpi.pcap"
OUTPUT_PCAP = "output/day18_output.pcap"

print("========== DAY 18 V1 INTEGRATION TEST ==========")

# --------------------------------------------------
# 1. Read input PCAP
# --------------------------------------------------

packets = rdpcap(INPUT_PCAP)

print("\n[1] Input PCAP")
print(f"Input packets: {len(packets)}")


# --------------------------------------------------
# 2. Create DPI engine
# --------------------------------------------------

engine = DPIEngine()


# --------------------------------------------------
# 3. Process packets
# --------------------------------------------------

parsed_packets, protocol_statistics, decisions, forwarded_packets = (
    engine.process_packets(packets)
)


print("\n[2] Packet Processing")
print(f"Parsed packets: {len(parsed_packets)}")
print(f"Decisions: {len(decisions)}")
print(f"Forwarded packets: {len(forwarded_packets)}")


# --------------------------------------------------
# 4. Protocol statistics
# --------------------------------------------------

print("\n[3] Protocol Statistics")

for protocol, count in protocol_statistics.items():
    print(f"{protocol}: {count}")


# --------------------------------------------------
# 5. Enforcement statistics
# --------------------------------------------------

forward_count = decisions.count("FORWARD")
drop_count = decisions.count("DROP")

print("\n[4] Enforcement")
print(f"FORWARD: {forward_count}")
print(f"DROP: {drop_count}")


# --------------------------------------------------
# 6. Flow tracking
# --------------------------------------------------

total_flows = engine.connection_tracker.get_flow_count()

sni_flows = [
    flow
    for flow in engine.connection_tracker.flows.values()
    if flow.sni
]

print("\n[5] Flow Tracking")
print(f"Total flows: {total_flows}")
print(f"Flows with SNI: {len(sni_flows)}")


# --------------------------------------------------
# 7. SNI / Application report
# --------------------------------------------------

print("\n[6] SNI / Application Report")

for flow in sni_flows:

    decision = "DROP" if flow.blocked else "FORWARD"

    print(
        f"{flow.sni} -> "
        f"{flow.app_type.name} -> "
        f"{decision}"
    )


# --------------------------------------------------
# 8. Write filtered output PCAP
# --------------------------------------------------

wrpcap(OUTPUT_PCAP, forwarded_packets)

print("\n[7] Output PCAP")
print(f"Output PCAP: {OUTPUT_PCAP}")
print(f"Output packets: {len(forwarded_packets)}")


# --------------------------------------------------
# 9. Verify input vs output
# --------------------------------------------------

output_packets = rdpcap(OUTPUT_PCAP)

print("\n[8] PCAP Verification")

print(f"Input packets: {len(packets)}")
print(f"Output packets: {len(output_packets)}")
print(f"Dropped packets: {drop_count}")


packet_count_pass = (
    len(packets) == len(output_packets) + drop_count
)

if packet_count_pass:
    print("Packet count verification: PASS")
else:
    print("Packet count verification: FAIL")


# --------------------------------------------------
# 10. Verify decisions
# --------------------------------------------------

decision_count_pass = (
    len(decisions) == len(packets)
)

if decision_count_pass:
    print("Decision count verification: PASS")
else:
    print("Decision count verification: FAIL")


# --------------------------------------------------
# 11. Verify output filtering
# --------------------------------------------------

output_filter_pass = (
    len(output_packets) == forward_count
)

if output_filter_pass:
    print("Output filtering verification: PASS")
else:
    print("Output filtering verification: FAIL")


# --------------------------------------------------
# 12. Final verification
# --------------------------------------------------

all_passed = (
    len(parsed_packets) == len(packets)
    and decision_count_pass
    and packet_count_pass
    and output_filter_pass
)

print("\n========== FINAL VERIFICATION ==========")

if all_passed:
    print("V1 integration test: PASS")
else:
    print("V1 integration test: FAIL")