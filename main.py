from src.pcap_reader import PcapReader
from src.packet_parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.connection_tracker import ConnectionTracker
from src.types import AppType
from src.v2.pipeline import V2Pipeline
from scapy.all import wrpcap
import argparse
import json

def parse_arguments():
    """
    Parse command-line arguments for the DPI engine.
    """

    # Create the command-line argument parser.
    parser = argparse.ArgumentParser(description="Python Deep Packet Inspection (DPI) Engine")

    # Allow the user to specify the input PCAP file.
    parser.add_argument("--input", default="input/test_dpi.pcap", help="Path to the input PCAP file.",)

    # Allow the user to specify where the filtered PCAP is written.
    parser.add_argument("--output", default="output/v2_filtered_output.pcap", help="Path to the filtered output PCAP file.",)
    parser.add_argument("--v1-output", default="output/v1_filtered_output.pcap", help="Path to the V1 filtered output PCAP file.",)

    # Number of worker threads used by the V2 pipeline.
    parser.add_argument("--workers", type=int, default=4, help="Number of V2 worker threads.",)

    # Blocking rules. Repeat a flag to pass more than one value.
    # When a flag is not used, the built-in default rules apply.
    parser.add_argument("--block-ip", action="append", help="Block a source IP. Repeatable.",)
    parser.add_argument("--block-domain", action="append", help="Block a domain. Repeatable.",)
    parser.add_argument("--block-app", action="append", help="Block an app, e.g. FACEBOOK. Repeatable.",)
    return parser.parse_args()

def main():
    # Read command-line arguments.
    args = parse_arguments()

    print("Python DPI Engine")

    # Load packets from the selected PCAP file.
    reader = PcapReader(args.input)
    packets = reader.read_packets()

    # Create a parser to extract useful information from each packet.
    parser = PacketParser()

    # Store all parsed packets for future analysis.
    parsed_packets = []

    # Parse every packet from the PCAP file.
    for packet in packets:
        parsed_packet = parser.parse(packet)
        parsed_packets.append(parsed_packet)

    print(f"Successfully parsed {len(parsed_packets)} packets.")

    # Convert application names from the CLI into AppType values.
    blocked_apps = ([AppType(name.strip().upper()) for name in args.block_app] if args.block_app else None)

    # Create the connection Tracker object
    connection_tracker = ConnectionTracker(
        blocked_ips=args.block_ip,
        blocked_apps=blocked_apps,
        blocked_domains=args.block_domain,
    )

    # Create the analyzer object.
    analyzer = PacketAnalyzer(connection_tracker)

    # Analyze all parsed packets.
    protocol_statistics = analyzer.analyze(parsed_packets)

    print("\nApplication / Flow Statistics")
    print("-----------------------------------")
     
    for item in analyzer.sni_application_report:
        print(
            f"{item['sni']:<25} -> "
            f"{item['application']:<10} -> "
            f"{'DROP' if item['blocked'] else 'FORWARD'}"
        )

    print("\nApplication Statistics")
    print("-----------------------------------")

    for application, count in analyzer.application_count.items():
        print(f"{application:<15}: {count}")

    print("\nProtocol Statistics:")

    for protocol, count in protocol_statistics.items():
        print(f"{protocol}: {count} ({count / len(parsed_packets) * 100:.1f}%)")

    # Display the number of unique source IP addresses.
    print("\nUnique Source IPs:")
    print(len(analyzer.unique_source_ips))

    print("\nSource IP Packet Count:")

    for ip, count in analyzer.source_ip_count.items():
        print(f"{ip}: {count} packets")

    print("\nDestination Port Statistics:")

    for port, count in analyzer.destination_port_count.items():
        print(f"Port {port}: {count} packets")

    print("\nService Statistics:")

    for service, count in analyzer.service_count.items():
        print(f"{service}: {count} packets")

    print("\nTop Service:")
    print(analyzer.top_service)

    # Display total HTTP packets detected.
    print("\nHTTP Packet Statistics:")
    print(f"HTTP Packets: {analyzer.http_packet_count}")

    print(f"HTTPS Packets: {analyzer.https_packet_count}")
    print(f"TLS Handshakes: {analyzer.tls_handshake_count}")

    print("\nHTTP Response Statistics:")
    print(f"HTTP Responses: {analyzer.http_response_count}")

    for code, count in analyzer.http_status_codes.items():
        print(f"{code}: {count}")

    # Checking if this HTTP request is GET request or POST request
    print("\nHTTP Method Statistics:")
    for method, count in analyzer.http_method_count.items():
        print(f"{method}: {count}")

    print("\nHTTP Hosts:")
    for host in analyzer.http_hosts:
        print(host)

    print("\nTop HTTP Hosts:")
    for host, count in analyzer.http_host_count.items():
        print(f"{host}: {count}")

    print("\nHTTP User Agents:")
    for agent in analyzer.user_agents:
        print(agent)

    print("\nTop User Agents:")
    for agent, count in analyzer.user_agent_count.items():
        print(f"{agent}: {count}")

    print("\nHTTP Requested Paths:")
    for path in analyzer.http_paths:
        print(path)

    print("\nSNI Domains:")
    for domain in analyzer.sni_domains:
        print(domain)

    # Now will print the suspicious domains IF PRESENT
    print("\n========== SECURITY REPORT ==========")

    print(f"Total SNI Domains : {len(analyzer.sni_domains)}")

    print(f"Suspicious Domains Found : {len(analyzer.suspicious_domains)}")

    if analyzer.suspicious_domains:
        print("\nDetected Suspicious Domains:")

        for domain in analyzer.suspicious_domains:
            print("-", domain)
        print("\nRisk Level : HIGH")

    else:
        print("\nDetected Suspicious Domains : None Found")
        print("Risk Level : LOW")

    # Display the first parsed packet for verification.
    print("\nFirst Parsed Packet:")
    print(parsed_packets[0])

    # Now making the JSON report
    report = {
        "protocol_statistics": protocol_statistics,
        "http_packets": analyzer.http_packet_count,
        "https_packets": analyzer.https_packet_count,
        "tls_handshakes": analyzer.tls_handshake_count,
        "http_methods": analyzer.http_method_count,
        "http_hosts": analyzer.http_hosts,
        "http_paths": analyzer.http_paths,
        "sni_domains": analyzer.sni_domains,
        "suspicious_domains": analyzer.suspicious_domains,
        "risk_level": ( 
            "HIGH"
            if analyzer.suspicious_domains
            else "LOW"
        )
    }  

    with open("security_report.json", "w") as file:
        json.dump(report, file, indent=4)

    print("\nSecurity report saved as security_report.json")

    # Write the packets that V1 allowed to pass.
    wrpcap(args.v1_output, [packet for packet, parsed in zip(packets, parsed_packets) if not connection_tracker.is_packet_blocked(parsed)])

    print(f"V1 filtered PCAP saved as {args.v1_output}")

    # ==========================================
    # V2 MULTI-THREADED DPI PIPELINE
    # ==========================================

    print("\n")
    print("==========================================")
    print("       V2 MULTI-THREADED DPI ENGINE")
    print("==========================================")

    v2_pipeline = V2Pipeline(
        file_path=args.input,
        output_path=args.output,
        worker_count=args.workers,
        blocked_ips=args.block_ip,
        blocked_apps=blocked_apps,
        blocked_domains=args.block_domain,
    )

    v2_stats, v2_results, v2_application_stats = v2_pipeline.run()

    # The pipeline already counted all of this while building its report.
    v2_report = v2_pipeline.get_report()

    print("\nV2 DPI REPORT")
    print("==========================================")

    print(f"Total Processed : {v2_report['total_packets']}")
    print(f"Forwarded       : {v2_report['forwarded']}")
    print(f"Dropped         : {v2_report['dropped']}")
    print(f"Skipped Non-IP  : {v2_report['skipped']}")
    print(f"Total Flows     : {v2_report['total_flows']}")
    print(f"Worker Errors   : {sum(v2_report['errors'].values())}")

    print("\nApplication Statistics")
    print("------------------------------------------")

    for application, count in v2_application_stats.items():
        print(f"{application:<15}: {count}")

    print("\nWorker Statistics")
    print("------------------------------------------")

    for worker_id, count in v2_stats.items():
        print(f"Worker {worker_id:<9}: {count} packets")

    print("\nOutput")
    print("------------------------------------------")
    print(f"Filtered PCAP   : {args.output}")

    print("\n==========================================")
    print("       V2 PIPELINE COMPLETED")
    print("==========================================")

if __name__ == "__main__":
    main()
