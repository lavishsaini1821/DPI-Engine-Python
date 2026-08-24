from src.v2.flow_balancer import FlowKey
from src.v2.worker_pool import WorkerPool

def create_flow(
    src_port: int,
    dst_port: int = 443,
) -> FlowKey:

    return FlowKey(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
    )

def test_packet_goes_to_selected_worker():

    pool = WorkerPool(worker_count=4, processor=lambda packet: None,)

    flow = create_flow(5000)

    worker_id = pool.submit(
        flow,
        "packet-1",
    )
    queue = pool.get_queue(worker_id)

    assert queue.pop() == "packet-1"
    queue.task_done()

def test_same_flow_uses_same_worker():

    pool = WorkerPool(worker_count=4, processor=lambda packet: None,)

    flow = create_flow(5000)

    worker_1 = pool.submit(
        flow,
        "packet-1",
    )

    worker_2 = pool.submit(
        flow,
        "packet-2",
    )
    assert worker_1 == worker_2

    queue = pool.get_queue(worker_1)

    assert queue.pop() == "packet-1"
    assert queue.pop() == "packet-2"

    queue.task_done()
    queue.task_done()

def test_multiple_flows_can_use_different_workers():

    pool = WorkerPool(worker_count=4, processor=lambda packet: None,)

    workers = set()

    for port in range(5000, 5100):

        flow = create_flow(port)

        worker_id = pool.submit(
            flow,
            f"packet-{port}",
        )

        workers.add(worker_id)

    assert workers.issubset({0, 1, 2, 3})
    assert len(workers) > 1

def test_reverse_direction_stays_on_same_worker():

    pool = WorkerPool(worker_count=4, processor=lambda packet: None,)

    forward = FlowKey(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=443,
        protocol="TCP",
    )

    reverse = FlowKey(
        src_ip="10.0.0.2",
        dst_ip="10.0.0.1",
        src_port=443,
        dst_port=5000,
        protocol="TCP",
    )

    worker_1 = pool.submit(
        forward,
        "forward-packet",
    )

    worker_2 = pool.submit(
        reverse,
        "reverse-packet",
    )
    assert worker_1 == worker_2

    queue = pool.get_queue(worker_1)

    assert queue.pop() == "forward-packet"
    assert queue.pop() == "reverse-packet"

    queue.task_done()
    queue.task_done()

if __name__ == "__main__":

    test_packet_goes_to_selected_worker()
    test_same_flow_uses_same_worker()
    test_multiple_flows_can_use_different_workers()
    test_reverse_direction_stays_on_same_worker()

    print("V2 Worker Pool Tests: PASS")