from scapy.all import IP, TCP, Raw
from src.v2.worker_pool import WorkerPool
from src.v2.dpi_processor import DPIProcessor
from src.v2.flow_balancer import FlowKey

def create_packet(port: int):

    return (
        IP(
            src="10.0.0.1",
            dst="10.0.0.2",
        )
        / TCP(
            sport=port,
            dport=443,
        )
        / Raw(
            load=b"hello",
        )
    )

def create_flow(port: int):

    return FlowKey(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=port,
        dst_port=443,
        protocol="TCP",
    )

def test_full_v2_pipeline():

    processor = DPIProcessor()
    pool = WorkerPool(
        worker_count=4,
        processor=processor.process,
    )

    pool.start()
    total_packets = 100

    for packet_id in range(total_packets):
        port = 5000 + (packet_id % 20)
        pool.submit(
            create_flow(port),
            create_packet(port),
        )

    pool.wait_until_empty()
    stats = pool.get_worker_stats()
    pool.stop()
    pool.join()
    processed_packets = sum(stats.values())

    assert processed_packets == total_packets

    print("Worker Statistics:")

    for worker_id, count in stats.items():
        print(
            f"Worker {worker_id}: {count} packets"
        )

if __name__ == "__main__":

    test_full_v2_pipeline()

    print(
        "V2 Full Pipeline Test: PASS"
    )