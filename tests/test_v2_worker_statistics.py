from src.v2.flow_balancer import FlowKey
from src.v2.worker_pool import WorkerPool

def create_flow(port: int) -> FlowKey:
    return FlowKey(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=port,
        dst_port=443,
        protocol="TCP",
    )

def test_worker_statistics():

    processed = []

    def processor(packet):
        processed.append(packet)

    pool = WorkerPool(
        worker_count=4,
        processor=processor,
    )
    pool.start()
    total_packets = 1000

    for packet_id in range(total_packets):

        flow = create_flow(
            5000 + (packet_id % 100)
        )

        pool.submit(
            flow,
            packet_id,
        )
    pool.wait_until_empty()
    stats = pool.get_worker_stats()
    pool.stop()
    pool.join()

    total_processed = sum(stats.values())

    assert total_processed == total_packets

    assert len(stats) == 4

    assert all(
        count >= 0
        for count in stats.values()
    )

    print("\nWorker Statistics:")

    for worker_id, count in stats.items():
        print(
            f"Worker {worker_id}: "
            f"{count} packets"
        )

if __name__ == "__main__":

    test_worker_statistics()

    print("\nV2 Worker Statistics Test: PASS")