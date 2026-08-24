from scapy.all import rdpcap


class PcapReader:

    def __init__(self, file_path):
        self.file_path = file_path

    def read_packets(self):
        packets = rdpcap(self.file_path)
        return packets