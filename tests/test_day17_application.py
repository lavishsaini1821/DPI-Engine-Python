from src.pcap_reader import PcapReader
from src.dpi_engine import DPIEngine


# Read packets from the input PCAP.
reader = PcapReader("input/test_dpi.pcap")
packets = reader.read_packets()

# Process packets through the DPI engine.
engine = DPIEngine()

engine.process_packets(packets)


print("========== DAY 17 APPLICATION BREAKDOWN ==========")

for application, count in sorted(
    engine.analyzer.application_count.items()
):
    print(f"{application}: {count}")


# Verify that application statistics were generated.
if engine.analyzer.application_count:
    print("Application breakdown: PASS")
else:
    print("Application breakdown: FAIL")

assert engine.analyzer.application_count