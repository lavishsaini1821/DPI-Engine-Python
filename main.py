import os
from src.pcap_reader import PcapReader
from src.packet_parser import PacketParser
from src.analyzer import PacketAnalyzer
from src.connection_tracker import ConnectionTracker
from src.types import AppType
from src.v2.pipeline import V2Pipeline
from src.live_capture import LivePacketCapture
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

    # Live capture mode: capture packets live via Npcap/Scapy instead of
    # reading from a PCAP file. The offline/PCAP path is unchanged when
    # --live is not used.
    parser.add_argument("--live", action="store_true", help="Capture packets live via Npcap/Scapy instead of reading from a PCAP file.",)
    parser.add_argument("--interface", default=None, help="Network interface for live capture (name, index, or NDIS device path).",)
    parser.add_argument("--timeout", type=int, default=10, help="Seconds to sniff in live mode (0 = no timeout).",)
    parser.add_argument("--filter", default=None, help="BPF expression for live capture, e.g. 'tcp and port 443'.",)
    parser.add_argument("--stop-after", type=int, default=None, help="Capture this many packets then stop in live mode.",)
    parser.add_argument("--pcap-save", default=None, help="Save captured live packets to this PCAP path.",)
    return parser.parse_args()

def main():
    # Read command-line arguments.
    args = parse_arguments()

    print("Python DPI Engine")

    # Load packets: live capture mode or offline PCAP mode.
    if args.live:
        # Live capture via Npcap/Scapy
        print("Starting live packet capture...")
        capture = LivePacketCapture(
            interface=args.interface,
            promiscuous=True,  # default, could be made configurable
            timeout=args.timeout,
            filter=args.filter,
            stop_after=args.stop_after,
            pcap_save=args.pcap_save,
        )
        packets = capture.sniff()

        # Warn if live capture fell back to PCAP/Parquet replay
        if args.pcap_save is None and len(packets) > 0:
            print(f"Captured {len(packets)} packets via live capture.")
        elif args.pcap_save is not None:
            print(f"Captured {len(packets)} packets (saved to {args.pcap_save}).")
        else:
            print("Warning: No packets captured in live mode.")

        # For V2Pipeline, write captured packets to a temporary PCAP
        import tempfile
        temp_pcap_fd, temp_pcap_path = tempfile.mkstemp(suffix='.pcap', prefix='dpi_live_')
        os.close(temp_pcap_fd)  # Close the file descriptor, we'll write via wrpcap
        try:
            wrpcap(temp_pcap_path, packets)
            v2_input_path = temp_pcap_path
            print(f"Live packets written to temporary PCAP: {v2_input_path}")
        except Exception as e:
            print(f"Warning: Could not write temporary PCAP for V2 pipeline: {e}")
            v2_input_path = args.input  # Fallback to original input (may cause issues)
    else:
        # Offline PCAP mode (original behavior)
        print(f"Reading packets from PCAP file: {args.input}")
        reader = PcapReader(args.input)
        packets = reader.read_packets()
        v2_input_path = args.input

    # Create a parser to extract useful information from each packet.
    parser = PacketParser()

    # Store all parsed packets for future analysis.
    parsed_packets = []

    # Parse every packet from the PCAP file.
    for packet in packets:
        parsed_packet = parser.parse(packet)
        parsed_packets.append(parsed_packet)

    print(f"Successfully processed {len(parsed_packets)} packets.")

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

    # ============================================================
    # Data Engineering Phases 1-5
    # ============================================================
    # Phase 1: Parquet — emit structured events to columnar storage.
    # Guarded so the DPI pipeline still runs when pyarrow is missing.
    events = []
    try:
        from src.data_engineering.emitter import NetworkEventEmitter
        from src.data_engineering.parquet_sink import ParquetSink

        decisions = [
            "DROP" if connection_tracker.is_packet_blocked(p) else "FORWARD"
            for p in parsed_packets
        ]
        events = NetworkEventEmitter(
            parsed_packets, decisions, connection_tracker
        ).emit_all()
        parquet_path = "output/network_events.parquet"
        ParquetSink().write(events, parquet_path)
        print(f"\nParquet events written: {parquet_path} ({len(events)} events)")
    except ImportError:
        pass  # DE layer not installed — DPI output is unaffected

    # Phase 2: PySpark ETL — transform Parquet events with Spark.
    # Guarded so the DPI pipeline still runs when pyspark/Java is missing.
    try:
        from src.data_engineering.pyspark_etl import NetworkEventETL

        etl = NetworkEventETL()
        etl.run(
            input_path="output/network_events.parquet",
            output_path="output/pyspark_etl_output"
        )
    except ImportError:
        pass  # ETL layer not installed — DPI + Phase 1 unaffected

    # Phase 3: PostgreSQL — persist structured events to a relational DB.
    # Guarded so the DPI pipeline still runs when psycopg2 is missing.
    try:
        from src.data_engineering.postgres_sink import PostgresSink

        if os.getenv('DPI_SKIP_EXTERNAL_SINKS') != '1':
            PostgresSink().write(
                events,
            connection_string="dbname=dpi user=postgres password=secret host=localhost port=5432",
            table="network_events",
            )
            print(f"\nPostgreSQL: {len(events)} rows written to 'network_events'.")
    except ImportError:
        pass  # PostgresSink not installed — DPI + Phases 1-2 unaffected

    # Phase 4: Kafka — publish events as JSON messages for streaming consumers.
    # Guarded so the DPI pipeline still runs when kafka-python is missing.
    try:
        from src.data_engineering.kafka_sink import KafkaSink

        if os.getenv('DPI_SKIP_EXTERNAL_SINKS') != '1':
            KafkaSink().publish(events, topic='network_events')
            print(f"\nKafka: {len(events)} events published to 'network_events'.")
    except ImportError:
        pass  # KafkaSink not installed — DPI + Phases 1-3 unaffected

    # Phase 5: Airflow hook — the DAG is defined in airflow_dag.py and picked up
    # by the scheduler. When Airflow is missing, DAG is None — no effect here.
    try:
        from src.data_engineering.airflow_dag import DAG as _AirflowDAG

        if _AirflowDAG is not None:
            print("\nAirflow DAG 'dpi_data_engineering_pipeline' registered.")
    except ImportError:
        pass  # Airflow not installed — DPI + Phases 1-4 unaffected

    # ============================================================
    # V2 MULTI-THREADED DPI PIPELINE
    # ==========================================

    print("\n")
    print("==========================================")
    print("       V2 MULTI-THREADED DPI ENGINE")
    print("==========================================")

    v2_pipeline = V2Pipeline(
        file_path=v2_input_path,
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








