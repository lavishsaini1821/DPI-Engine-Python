from src.sni_extractor import SNIExtractor
from src.connection_tracker import ConnectionTracker
from src.types import FiveTuple

class PacketAnalyzer:
    """
    Performs analysis on parsed packets.
    """

    def __init__(self, connection_tracker):

        # Store total HTTP packets detected.
        self.http_packet_count = 0

        # Store total HTTPS packets detected.
        self.https_packet_count = 0

        # Store total TLS handshakes.
        self.tls_handshake_count = 0

        # Store HTTP request method statistics.
        self.http_method_count = {
            "GET": 0,
            "POST": 0
        }
        # Store detected HTTP host names.
        self.http_hosts = []

        # Store HTTP User-Agents.
        self.user_agents = []

        # Store requested HTTP paths.
        self.http_paths = []

        # Store protocol statistics.
        self.protocol_count = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0
        }

        # Store the total size of all captured packets in bytes.
        self.total_bytes = 0

        # Store unique source IP addresses.
        self.unique_source_ips = set()

        # Store packet count for every source IP.
        self.source_ip_count = {}

        # Store packet count for every destination port.
        self.destination_port_count = {}

        # Store detected application services.
        self.service_count = {}

        # Store the number of packets/flows associated with each application.
        self.application_count = {}

        # Store the most used network service.
        self.top_service = None

        # Store HTTP response status codes.
        self.http_status_codes = {}

        # Store total HTTP responses.
        self.http_response_count = 0

        # Count packets for each HTTP host.
        self.http_host_count = {}

        # Count occurrences of User-Agents.
        self.user_agent_count = {}

        # SNI EXTRACTOR
        self.sni_extractor = SNIExtractor()
        self.sni_domains = []

        # Store detected SNI and their classified applications.
        self.sni_application_report = []

        # Use the same flow tracker as the DPI engine.
        self.connection_tracker = connection_tracker

        # Seeking for SUSPICIOUS DOMAINS
        self.suspicious_domains = []
        self.blacklist = {
            "malicious.com",
            "phishing.com",
            "evil-site.net",
            "fake-login.com"
        }

    def analyze(self, parsed_packets):
        """
        Analyze every parsed packet and count protocols.
        """

        for packet in parsed_packets:

            # Add the complete size of the current packet.
            self.total_bytes += packet.get("packet_length", 0)

            # Collect unique source IP addresses.
            source_ip = packet.get("src_ip")

            if source_ip:
                self.unique_source_ips.add(source_ip)
                # Count packets sent by each source IP.

                if source_ip not in self.source_ip_count:
                    self.source_ip_count[source_ip] = 0

                self.source_ip_count[source_ip] += 1

            # Count packets received by each destination port.
            destination_port = packet.get("dst_port")

            # Map destination ports to application services.
            service_map = {
                80: "HTTP",
                443: "HTTPS",
                53: "DNS",
                22: "SSH",
                21: "FTP",
                25: "SMTP"
            }

            service = service_map.get(destination_port)

            if service:

                if service not in self.service_count:
                    self.service_count[service] = 0

                self.service_count[service] += 1

            if destination_port:

                if destination_port not in self.destination_port_count:
                    self.destination_port_count[destination_port] = 0

                self.destination_port_count[destination_port] += 1

                # Detect HTTPS packets using destination port.
                if destination_port == 443:
                    self.https_packet_count += 1

                # Extract payload for HTTP and TLS analysis
                payload = packet.get("payload", b"")

                # Giving the packet payload to SNI EXTRACTOR
                sni = self.sni_extractor.extract(payload)

                # If SNI found then save it into list
                if sni:
                    self.sni_domains.append(sni)

                # Checking if DOMAIN is SUSPICIOUS by putting it in Blacklist 
                    if sni.lower() in self.blacklist:
                        self.suspicious_domains.append(sni)

                # Detect TLS Handshake.
                if payload and len(payload) > 0:

                    # Debug print removed after payload verification. " print(payload[:20]) "

                    if payload[0] == 0x16:
                        self.tls_handshake_count += 1   

                try:
                    payload_text = payload.decode(errors="ignore")

                    for line in payload_text.split("\r\n"):

                        if line.startswith("Host:"):
                            host = line.replace("Host:", "").strip()
                            self.http_hosts.append(host)

                            if host not in self.http_host_count:
                                self.http_host_count[host] = 0

                            self.http_host_count[host] += 1

                    if "User-Agent:" in payload_text:

                        user_agent = payload_text.split("User-Agent:")[1]
                        user_agent = user_agent.split("\r\n")[0]
                        user_agent = user_agent.strip()

                        self.user_agents.append(user_agent)

                        if user_agent not in self.user_agent_count:
                            self.user_agent_count[user_agent] = 0

                        self.user_agent_count[user_agent] += 1
                        
                        # Detect HTTP Responses.
                    if payload_text.startswith("HTTP/"):

                        self.http_response_count += 1
                        status_code = payload_text.split(" ")[1]

                        if status_code not in self.http_status_codes:
                            self.http_status_codes[status_code] = 0
                        self.http_status_codes[status_code] += 1

                     # Extract requested HTTP path.
                    if (
                        payload_text.startswith("GET")
                        or payload_text.startswith("POST")
                    ):
                        path = payload_text.split(" ")[1]
                        self.http_paths.append(path)

                    if (
                        payload_text.startswith("GET")
                        or payload_text.startswith("POST")
                        or payload_text.startswith("PUT")
                        or payload_text.startswith("DELETE")
                           ):
                        self.http_packet_count += 1

                     # Count HTTP request methods.
                    if payload_text.startswith("GET"):
                        self.http_method_count["GET"] += 1

                    elif payload_text.startswith("POST"):
                        self.http_method_count["POST"] += 1

                except Exception:
                    pass

                # Create a Five-Tuple for flow tracking.
                src_ip = packet.get("src_ip")
                dst_ip = packet.get("dst_ip")
                src_port = packet.get("src_port", 0)
                dst_port = packet.get("dst_port", 0)
                protocol = packet.get("protocol")

                if src_ip and dst_ip and protocol:
                    five_tuple = FiveTuple(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=protocol
                    )

                    self.connection_tracker.get_or_create_flow(five_tuple, sni = sni )

            protocol = packet.get("protocol")

            if protocol == "TCP":
                self.protocol_count["TCP"] += 1

            elif protocol == "UDP":
                self.protocol_count["UDP"] += 1

            elif protocol == "ICMP":
                self.protocol_count["ICMP"] += 1

        # Find the most frequently used service.
        if self.service_count:
            self.top_service = max(
                self.service_count,
                key=self.service_count.get
            )

        # Count applications based on tracked network flows.
        self.application_count = {}

        # Build a report of detected SNI and classified applications.
        self.sni_application_report = []

        for flow in self.connection_tracker.flows.values():
            app_type = flow.app_type

            if app_type:
                app_name = app_type.name
            else:
                app_name = "UNKNOWN"

            if app_name not in self.application_count:
                self.application_count[app_name] = 0

            self.application_count[app_name] += 1

        for flow in self.connection_tracker.flows.values():
            if flow.sni:
                self.sni_application_report.append({
                    "sni": flow.sni,
                    "application": (
                        flow.app_type.name
                        if flow.app_type
                        else "UNKNOWN"
                    ),
                    "blocked": flow.blocked
                })

        return self.protocol_count