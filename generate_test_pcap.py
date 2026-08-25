from scapy.all import IP, TCP, UDP, Raw, wrpcap
import argparse

# Client that generates the HTTPS traffic.
CLIENT_IP = "192.168.1.100"

# Client that generates the plain HTTP and DNS traffic.
HTTP_CLIENT_IP = "192.168.1.50"

# Domains sent as TLS SNI, each with the server that answers it.
TLS_DOMAINS = [
    ("www.google.com", "142.250.185.206"),
    ("www.youtube.com", "142.250.185.110"),
    ("www.facebook.com", "157.240.1.35"),
    ("www.instagram.com", "157.240.1.174"),
    ("twitter.com", "104.244.42.65"),
    ("www.amazon.com", "52.94.236.248"),
    ("www.netflix.com", "23.52.167.61"),
    ("github.com", "140.82.114.4"),
    ("discord.com", "104.16.85.20"),
    ("zoom.us", "35.186.224.25"),
    ("web.telegram.org", "35.186.227.140"),
    ("www.tiktok.com", "99.86.0.100"),
    ("open.spotify.com", "35.186.224.47"),
    ("www.cloudflare.com", "192.0.78.24"),
    ("www.microsoft.com", "13.107.42.14"),
    ("www.apple.com", "17.253.144.10"),
]

# Plain HTTP requests, each with the server that answers it.
HTTP_HOSTS = [
    ("example.com", "93.184.216.34"),
    ("httpbin.org", "34.227.213.82"),
]


def build_client_hello(domain):
    """
    Build a minimal TLS ClientHello carrying the given domain as SNI.

    The layout follows RFC 8446 closely enough for SNIExtractor:
    record header (5) + handshake header (4) + client version (2)
    + random (32) puts the session ID length at byte 43.
    """

    host = domain.encode()

    # server_name extension: list length, name type, host name.
    server_name_list = b"\x00" + len(host).to_bytes(2, "big") + host
    extension_data = len(server_name_list).to_bytes(2, "big") + server_name_list

    # Extension type 0x0000 is server_name (SNI).
    extension = b"\x00\x00" + len(extension_data).to_bytes(2, "big") + extension_data
    extensions = len(extension).to_bytes(2, "big") + extension

    # Client version, random, and an empty session ID.
    body = b"\x03\x03" + bytes(32) + b"\x00"

    # One cipher suite and one compression method.
    body += b"\x00\x02\x00\x2f" + b"\x01\x00" + extensions

    # Handshake header: ClientHello type and a 3 byte length.
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body

    # Record header: handshake content type, version, and length.
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def build_packets():
    """
    Build the full list of test packets.

    Produces 73 TCP and 4 UDP packets, so the totals match
    the capture the test suite expects.
    """

    packets = []
    source_port = 54000

    # TLS flows: a handshake and a ClientHello from the client,
    # then a single reply from the server.
    for domain, server_ip in TLS_DOMAINS:
        source_port += 1

        packets.append(
            IP(src=CLIENT_IP, dst=server_ip)
            / TCP(sport=source_port, dport=443, flags="S")
        )

        packets.append(
            IP(src=CLIENT_IP, dst=server_ip)
            / TCP(sport=source_port, dport=443, flags="PA")
            / Raw(load=build_client_hello(domain))
        )

        packets.append(
            IP(src=server_ip, dst=CLIENT_IP)
            / TCP(sport=443, dport=source_port, flags="SA")
        )

    # HTTP flows: a handshake and a GET request carrying a Host header.
    for host, server_ip in HTTP_HOSTS:
        source_port += 1

        packets.append(
            IP(src=HTTP_CLIENT_IP, dst=server_ip)
            / TCP(sport=source_port, dport=80, flags="S")
        )

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: DPI-Test/1.0\r\n\r\n"
        )

        packets.append(
            IP(src=HTTP_CLIENT_IP, dst=server_ip)
            / TCP(sport=source_port, dport=80, flags="PA")
            / Raw(load=request.encode())
        )

    # Encrypted traffic with no SNI, so it stays unclassified.
    for index in range(21):
        source_port += 1

        packets.append(
            IP(src=CLIENT_IP, dst="8.8.8.8")
            / TCP(sport=source_port, dport=443, flags="PA")
            / Raw(load=bytes([index]) * 32)
        )

    # DNS queries, the only UDP traffic in the capture.
    for index in range(4):
        source_port += 1

        packets.append(
            IP(src=HTTP_CLIENT_IP, dst="8.8.4.4")
            / UDP(sport=source_port, dport=53)
            / Raw(load=b"\x00\x01\x01\x00" + bytes(8))
        )

    return packets


def parse_arguments():
    """
    Parse command-line arguments for the generator.
    """

    parser = argparse.ArgumentParser(description="Generate a test PCAP file for the DPI engine")

    # Allow the user to choose where the capture is written.
    parser.add_argument("--output", default="input/test_dpi.pcap", help="Path to the generated PCAP file.",)
    return parser.parse_args()


def main():
    args = parse_arguments()
    packets = build_packets()

    wrpcap(args.output, packets)

    print(f"Generated {len(packets)} packets -> {args.output}")
    print(f"TLS flows with SNI : {len(TLS_DOMAINS)}")
    print(f"HTTP requests      : {len(HTTP_HOSTS)}")


if __name__ == "__main__":
    main()
