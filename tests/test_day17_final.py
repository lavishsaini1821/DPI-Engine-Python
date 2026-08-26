from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine


# Read packets from the input PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Process all packets through the DPI engine.
engine = DPIEngine()

(
    parsed_packets,
    protocol_statistics,
    decisions,
    forwarded_packets
) = engine.process_packets(packets)


analyzer = engine.analyzer


print("========== DAY 17 FINAL VERIFICATION ==========")

# -------------------------------------------------
# Packet statistics
# -------------------------------------------------

print("Packet Statistics:")
print(f"Total packets: {len(parsed_packets)}")
print(f"Total bytes: {analyzer.total_bytes}")

# -------------------------------------------------
# Application breakdown
# -------------------------------------------------

print("\nApplication Breakdown:")

for application, count in sorted(
    analyzer.application_count.items()
):
    print(f"{application}: {count}")

# -------------------------------------------------
# SNI / Application report
# -------------------------------------------------

print("\nSNI/Application Report:")

for entry in analyzer.sni_application_report:
    decision = "DROP" if entry["blocked"] else "FORWARD"

    print(
        f"{entry['sni']} -> "
        f"{entry['application']} -> "
        f"{decision}"
    )

# -------------------------------------------------
# Enforcement statistics
# -------------------------------------------------

forward_count = decisions.count("FORWARD")
drop_count = decisions.count("DROP")

print("\nEnforcement:")
print(f"FORWARD: {forward_count}")
print(f"DROP: {drop_count}")

# -------------------------------------------------
# Verification
# -------------------------------------------------

print("\nVerification:")

bytes_pass = analyzer.total_bytes == 5738

application_pass = (
    analyzer.application_count.get("FACEBOOK") == 1
    and analyzer.application_count.get("GOOGLE") == 1
    and analyzer.application_count.get("YOUTUBE") == 1
    and analyzer.application_count.get("GITHUB") == 1
    and sum(analyzer.application_count.values()) == 43
)

sni_pass = len(analyzer.sni_application_report) == 16

enforcement_pass = forward_count == 76 and drop_count == 1


print("Total bytes:", "PASS" if bytes_pass else "FAIL")
print("Application breakdown:", "PASS" if application_pass else "FAIL")
print("SNI/application report:", "PASS" if sni_pass else "FAIL")
print("Enforcement:", "PASS" if enforcement_pass else "FAIL")

assert bytes_pass
assert application_pass
assert sni_pass
assert enforcement_pass