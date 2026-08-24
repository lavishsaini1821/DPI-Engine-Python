from scapy.all import IP, TCP, UDP


class PacketParser:

    def parse(self, packet):
        result = {}

        # Store the complete packet size including headers.
        result["packet_length"] = len(packet)

        if IP in packet:
            result["src_ip"] = packet[IP].src
            result["dst_ip"] = packet[IP].dst

            # Convert protocol number into a readable protocol name.
            protocol_map = {
                1: "ICMP",
                6: "TCP",
                17: "UDP"
            }

            protocol_number = packet[IP].proto
            result["protocol"] = protocol_map.get(protocol_number, "UNKNOWN")

        if TCP in packet:
            result["src_port"] = packet[TCP].sport
            result["dst_port"] = packet[TCP].dport

        elif UDP in packet:
            result["src_port"] = packet[UDP].sport
            result["dst_port"] = packet[UDP].dport

        # Extract the RAW Payload from TCP header
        # Extract TCP Application Payload
        if TCP in packet:
            result["payload"] = bytes(packet[TCP].payload)

        elif UDP in packet:
            result["payload"] = bytes(packet[UDP].payload)    

        return result