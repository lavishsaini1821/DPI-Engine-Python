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

def test_worker_pool_processes_packets_concurrently():

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

    pool.stop()
    pool.join()

    assert len(processed) == total_packets
    assert sorted(processed) == list(
        range(total_packets)
    )

def test_same_flow_is_assigned_to_same_worker():

    processed = []

    def processor(packet):
        processed.append(packet)

    pool = WorkerPool(
        worker_count=4,
        processor=processor,
    )

    pool.start()

    flow = create_flow(5000)

    worker_ids = []

    for packet_id in range(20):

        worker_id = pool.submit(
            flow,
            packet_id,
        )

        worker_ids.append(worker_id)

    pool.wait_until_empty()

    pool.stop()
    pool.join()

    assert len(set(worker_ids)) == 1
    assert len(processed) == 20

def test_multiple_flows_are_distributed():

    processed = []

    def processor(packet):
        processed.append(packet)

    pool = WorkerPool(
        worker_count=4,
        processor=processor,
    )

    pool.start()

    workers_used = set()

    for port in range(5000, 5100):

        flow = create_flow(port)

        worker_id = pool.submit(
            flow,
            port,
        )

        workers_used.add(worker_id)

    pool.wait_until_empty()

    pool.stop()
    pool.join()

    assert len(processed) == 100
    assert workers_used.issubset(
        {0, 1, 2, 3}
    )

    assert len(workers_used) > 1

if __name__ == "__main__":

    test_worker_pool_processes_packets_concurrently()
    test_same_flow_is_assigned_to_same_worker()
    test_multiple_flows_are_distributed()

    print(
        "V2 Worker Pool Integration Tests: PASS"
    )