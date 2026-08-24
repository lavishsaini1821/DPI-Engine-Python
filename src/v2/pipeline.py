from collections import Counter
from scapy.all import wrpcap
from src.packet_parser import PacketParser
from src.pcap_reader import PcapReader
from src.v2.dpi_processor import DPIProcessor
from src.v2.worker_pool import WorkerPool
from src.v2.flow_balancer import FlowKey


class V2Pipeline:
    """
    Runs the DPI processor using multiple workers.
    """
    def __init__(self,file_path,output_path="output/v2_filtered_output.pcap",worker_count=4,):

        self.reader = PcapReader(file_path)
        self.output_path = output_path

        # PacketParser holds no state, so one shared instance is safe.
        # It is used here only to build the FlowKey for balancing.
        self.parser = PacketParser()

        # Every worker gets its own DPIProcessor, and therefore its own
        # ConnectionTracker and flow table. Flow-hash affinity means a
        # flow always lands on the same worker, so no locking is needed.
        self.processors = []

        self.pool = WorkerPool(
            worker_count=worker_count,
            processor_factory=self._create_processor,
        )
        self.report = {}

    def _create_processor(self):
        """Create a per-worker DPI processor and keep a handle on it."""

        processor = DPIProcessor()
        self.processors.append(processor)

        return processor.process

    def run(self):
        packets = self.reader.read_packets()
        self.pool.start()

        # Packets we cannot key by five-tuple (ARP, IPv6, malformed).
        self.skipped_packets = 0

        for packet in packets:
            parsed = self.parser.parse(packet)

            # Non-IP packets have no addresses to balance on.
            if not parsed.get("src_ip") or not parsed.get("dst_ip"):
                self.skipped_packets += 1
                continue

            flow = FlowKey(
                src_ip=parsed["src_ip"],
                dst_ip=parsed["dst_ip"],
                src_port=parsed.get("src_port", 0),
                dst_port=parsed.get("dst_port", 0),
                protocol=parsed.get("protocol", "UNKNOWN"),
            )

            self.pool.submit(flow, packet)

        self.pool.wait_until_empty()
        stats = self.pool.get_worker_stats()
        results = self.pool.get_results()
        errors = self.pool.get_error_stats()

        self.pool.stop()
        self.pool.join()

        forwarded_packets = [
            result["raw_packet"]
            for result in results
            if result["decision"] == "FORWARD"
        ]

        wrpcap(self.output_path,forwarded_packets,)

        self.report = self._build_report(stats,results,errors,)

        return stats, results, self.report["applications"]

    def _build_report(self, stats, results, errors=None):

        decisions = Counter(
            result["decision"]
            for result in results
        )

        applications = Counter(
            result["flow"].app_type.value
            for result in results
            if result["flow"].app_type
        )

        return {
            "total_packets": len(results),
            "forwarded": decisions.get("FORWARD", 0),
            "dropped": decisions.get("DROP", 0),
            "skipped": getattr(self, "skipped_packets", 0),
            "applications": dict(applications),
            "workers": stats,
            "errors": errors or {},
            "total_flows": sum(
                processor.connection_tracker.get_flow_count()
                for processor in self.processors
            ),
        }

    def get_report(self):
        return self.report
