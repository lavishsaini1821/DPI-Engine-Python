from src.connection_tracker import ConnectionTracker


tracker = ConnectionTracker()


packet_1 = {
    "src_ip": "192.168.1.5",
    "dst_ip": "142.250.195.14",
    "src_port": 54552,
    "dst_port": 443,
    "protocol": "TCP"
}


packet_2 = {
    "src_ip": "192.168.1.5",
    "dst_ip": "142.250.195.14",
    "src_port": 54552,
    "dst_port": 443,
    "protocol": "TCP"
}


five_tuple_1 = tracker.create_five_tuple(packet_1)
flow_1 = tracker.get_or_create_flow(five_tuple_1, sni = "youtube.com")

five_tuple_2 = tracker.create_five_tuple(packet_2)
flow_2 = tracker.get_or_create_flow(five_tuple_2, "youtube")


print("Total flows:", tracker.get_flow_count())
print("Packet count in flow:", flow_1.packet_count)
print("Same flow:", flow_1 is flow_2)

# Display the Application Classification stored in the flow.
print("Flow SNI:", flow_1.sni)
print("Flow Application:", flow_1.app_type.value)