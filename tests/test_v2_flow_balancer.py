from src.v2.flow_balancer import FlowBalancer, FlowKey

def test_same_flow_same_worker():
    balancer = FlowBalancer(worker_count=4)

    flow = FlowKey(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=443,
        protocol="TCP",
    )

    worker_1 = balancer.get_worker(flow)
    worker_2 = balancer.get_worker(flow)

    assert worker_1 == worker_2
    assert 0 <= worker_1 < 4

def test_reverse_direction_same_worker():
    balancer = FlowBalancer(worker_count=4)

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
    assert balancer.get_worker(forward) == balancer.get_worker(reverse)

def test_different_flows_can_be_distributed():
    balancer = FlowBalancer(worker_count=4)

    workers = set()

    for port in range(5000, 5100):
        flow = FlowKey(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=port,
            dst_port=443,
            protocol="TCP",
        )

        workers.add(balancer.get_worker(flow))

    assert workers.issubset({0, 1, 2, 3})
    assert len(workers) > 1

def test_invalid_worker_count():
    try:
        FlowBalancer(worker_count=0)
        assert False
    except ValueError:
        pass

if __name__ == "__main__":
    test_same_flow_same_worker()
    test_reverse_direction_same_worker()
    test_different_flows_can_be_distributed()
    test_invalid_worker_count()

    print("V2 Flow Balancer Tests: PASS")