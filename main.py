from src.pcap_reader import PcapReader
from src.packet_parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.connection_tracker import ConnectionTracker
from src.v2.pipeline import V2Pipeline
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

    # Create the connection Tracker object
    connection_tracker = ConnectionTracker()

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
        print(f"{protocol}: {count}")

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

    # ==========================================
    # V2 MULTI-THREADED DPI PIPELINE
    # ==========================================

    print("\n")
    print("==========================================")
    print("       V2 MULTI-THREADED DPI ENGINE")
    print("==========================================")

    v2_pipeline = V2Pipeline(
        file_path=args.input,
        output_path="output/v2_filtered_output.pcap",
        worker_count=4,
    )

    v2_stats, v2_results, v2_application_stats = v2_pipeline.run()
    v2_total_processed = len(v2_results)
    v2_forwarded = sum(
        1
        for result in v2_results
        if result["decision"] == "FORWARD"
    )

    v2_dropped = sum(
        1
        for result in v2_results
        if result["decision"] == "DROP"
    )

    print("\nV2 DPI REPORT")
    print("==========================================")

    print(f"Total Processed : {v2_total_processed}")
    print(f"Forwarded       : {v2_forwarded}")
    print(f"Dropped         : {v2_dropped}")

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
    print(
        "Filtered PCAP   : "
        "output/v2_filtered_output.pcap"
    )

    print("\n==========================================")
    print("       V2 PIPELINE COMPLETED")
    print("==========================================")

if __name__ == "__main__":
    main()
