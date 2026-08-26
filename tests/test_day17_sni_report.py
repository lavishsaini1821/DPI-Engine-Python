from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine

# Read packets from the input PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Process packets through the DPI engine.
engine = DPIEngine()

engine.process_packets(packets)

report = engine.analyzer.sni_application_report

print("========== DAY 17 SNI/APPLICATION REPORT ==========")

for entry in report:
    print(
        f"SNI: {entry['sni']} | "
        f"Application: {entry['application']} | "
        f"Blocked: {entry['blocked']}"
    )

print(f"Total SNI entries: {len(report)}")

# Verify that SNI/application information was detected.
if len(report) == 16:
    print("SNI/application report: PASS")
else:
    print("SNI/application report: FAIL")

assert len(report) == 16