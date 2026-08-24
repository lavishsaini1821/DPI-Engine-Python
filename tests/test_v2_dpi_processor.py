from scapy.all import IP, TCP, Raw
from src.v2.dpi_processor import DPIProcessor

def create_packet():

    return (IP(src="10.0.0.1",dst="10.0.0.2",) / TCP(sport=5000,dport=443,) / Raw(load=b"hello"))

def create_tls_client_hello(hostname="www.google.com"):

    hostname = hostname.encode()

    # Server Name Indication structure:
    server_name = (b"\x00" + len(hostname).to_bytes(2, byteorder="big") + hostname)

    # Server Name List:
    # 2 bytes list length + server_name
    sni_list = (len(server_name).to_bytes(2, byteorder="big") + server_name)

    # SNI extension:
    # Extension Type = 0x0000
    # Extension Length
    # Extension Data = SNI list
    sni_extension = (b"\x00\x00" + len(sni_list).to_bytes(2, byteorder="big") + sni_list)

    # Extensions block:
    # Total extensions length + SNI extension
    extensions = (len(sni_extension).to_bytes(2, byteorder="big") + sni_extension)

    # TLS ClientHello body.
    # At offset 43:
    # Session ID length
    # This is exactly what the V1 SNIExtractor expects.
    client_hello_body = (
        b"\x03\x03"                    # TLS version
        + b"\x00" * 32                 # Random
        + b"\x00"                      # Session ID length
        + b"\x00\x02"                  # Cipher suite length
        + b"\x00\x2f"                  # TLS_RSA_WITH_AES_128_CBC_SHA
        + b"\x01"                      # Compression methods length
        + b"\x00"                      # Null compression
        + extensions
    )

    # TLS Handshake header:
    # Type 0x01 = ClientHello
    handshake = (
        b"\x01"
        + len(client_hello_body).to_bytes(3,byteorder="big") + client_hello_body
    )

    # TLS record header:
    # 0x16 = Handshake
    # 0x0301 = TLS 1.0 record version
    record = (
        b"\x16\x03\x01" + len(handshake).to_bytes(2,byteorder="big") + handshake
    )

    return (
        IP(src="10.0.0.1",dst="10.0.0.2",) / TCP(sport=5000,dport=443,) / Raw(load=record)
    )

def test_dpi_processor_parses_packet():

    processor = DPIProcessor()
    packet = create_packet()

    result = processor.process(packet)
    parsed = result["packet"]

    assert parsed["src_ip"] == "10.0.0.1"
    assert parsed["dst_ip"] == "10.0.0.2"
    assert parsed["protocol"] == "TCP"
    assert parsed["src_port"] == 5000
    assert parsed["dst_port"] == 443
    assert parsed["payload"] == b"hello"
    assert parsed["packet_length"] == len(packet)
    assert processor.packet_count == 1

def test_packet_belongs_to_flow():

    processor = DPIProcessor()
    packet = create_packet()

    result = processor.process(packet)
    flow = result["flow"]

    assert flow.five_tuple.src_ip == "10.0.0.1"
    assert flow.five_tuple.dst_ip == "10.0.0.2"
    assert flow.five_tuple.src_port == 5000
    assert flow.five_tuple.dst_port == 443
    assert flow.five_tuple.protocol == "TCP"
    assert flow.packet_count == 1

def test_same_flow_is_tracked_across_packets():

    processor = DPIProcessor()
    packet = create_packet()

    first_result = processor.process(packet)
    second_result = processor.process(packet)

    first_flow = first_result["flow"]
    second_flow = second_result["flow"]

    # Both packets should reference the same tracked flow.
    assert first_flow is second_flow
    assert first_flow.packet_count == 2
    assert processor.connection_tracker.get_flow_count() == 1

def test_sni_is_extracted_and_attached_to_flow():

    processor = DPIProcessor()
    packet = create_tls_client_hello()
    result = processor.process(packet)

    # The SNI extractor should identify the hostname
    # from the TLS ClientHello payload.
    assert result["sni"] == "www.google.com"

    # The extracted SNI should also be stored in the flow.
    assert result["flow"].sni == "www.google.com"

def test_sni_is_classified_as_application():

    processor = DPIProcessor()
    packet = create_tls_client_hello()
    result = processor.process(packet)
    flow = result["flow"]

    assert result["sni"] == "www.google.com"
    assert flow.app_type.value == "GOOGLE"

def test_blocked_application_is_dropped():

    processor = DPIProcessor()
    packet = create_tls_client_hello("www.facebook.com")
    result = processor.process(packet)
    flow = result["flow"]

    assert flow.app_type.value == "FACEBOOK"
    assert result["decision"] == "DROP"

def test_allowed_application_is_forwarded():

    processor = DPIProcessor()
    packet = create_tls_client_hello("www.google.com")
    result = processor.process(packet)
    flow = result["flow"]

    assert flow.app_type.value == "GOOGLE"
    assert result["decision"] == "FORWARD"

def test_http_host_is_extracted_and_attached_to_flow():
    processor = DPIProcessor()
    packet = (
        IP(src="10.0.0.1",dst="10.0.0.2",)

        / TCP(sport=5000,dport=80,)
        / Raw(
            load=(
                b"GET / HTTP/1.1\r\n"
                b"Host: www.google.com\r\n"
                b"\r\n"
            )
        )
    )

    result = processor.process(packet)

    assert result["http_host"] == "www.google.com"
    assert result["flow"].sni == "www.google.com"
    assert result["flow"].app_type.value == "GOOGLE"

if __name__ == "__main__":

    test_dpi_processor_parses_packet()
    test_packet_belongs_to_flow()
    test_same_flow_is_tracked_across_packets()
    test_sni_is_extracted_and_attached_to_flow()
    test_sni_is_classified_as_application()
    test_http_host_is_extracted_and_attached_to_flow()
    test_allowed_application_is_forwarded()
    test_blocked_application_is_dropped()

    print("V2 DPI Processor Tests: PASS")