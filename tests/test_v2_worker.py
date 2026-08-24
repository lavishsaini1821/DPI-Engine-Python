import time
from src.v2.thread_safe_queue import ThreadSafeQueue
from src.v2.worker import DPIWorker

def test_worker_processes_items():

    queue = ThreadSafeQueue()

    processed = []

    def processor(item):
        processed.append(item)

    worker = DPIWorker(
        worker_id=0,
        queue=queue,
        processor=processor,
    )

    worker.start()

    queue.push("packet-1")
    queue.push("packet-2")
    queue.push("packet-3")

    queue.join()

    worker.stop()
    worker.join()

    assert processed == [
        "packet-1",
        "packet-2",
        "packet-3",
    ]

def test_worker_runs_in_background_thread():

    queue = ThreadSafeQueue()

    processed = []

    def processor(item):
        processed.append(item)

    worker = DPIWorker(
        worker_id=1,
        queue=queue,
        processor=processor,
    )

    worker.start()

    queue.push("test-packet")

    queue.join()

    worker.stop()
    worker.join()

    assert processed == ["test-packet"]

if __name__ == "__main__":

    test_worker_processes_items()
    test_worker_runs_in_background_thread()

    print("V2 Worker Tests: PASS")