import threading
from src.v2.thread_safe_queue import ThreadSafeQueue

def test_basic_push_pop():
    queue = ThreadSafeQueue()

    queue.push("packet-1")
    queue.push("packet-2")

    assert queue.pop() == "packet-1"
    assert queue.pop() == "packet-2"

def test_multiple_producers_consumers():
    queue = ThreadSafeQueue()

    total_items = 1000
    produced = list(range(total_items))
    consumed = []

    def producer():
        for item in produced:
            queue.push(item)

    def consumer():
        for _ in produced:
            item = queue.pop()
            consumed.append(item)
            queue.task_done()

    producer_thread = threading.Thread(target=producer)
    consumer_thread = threading.Thread(target=consumer)

    producer_thread.start()
    consumer_thread.start()

    producer_thread.join()
    consumer_thread.join()

    assert len(consumed) == total_items
    assert sorted(consumed) == produced


def test_multiple_producers_and_consumers():
    queue = ThreadSafeQueue()

    producer_count = 4
    consumer_count = 4
    items_per_producer = 500

    produced_items = []
    consumed_items = []

    produced_lock = threading.Lock()
    consumed_lock = threading.Lock()

    def producer(producer_id):
        for item_id in range(items_per_producer):
            item = (producer_id, item_id)

            with produced_lock:
                produced_items.append(item)

            queue.push(item)

    def consumer():
        for _ in range(items_per_producer):
            item = queue.pop()

            with consumed_lock:
                consumed_items.append(item)

            queue.task_done()

    producers = [
        threading.Thread(
            target=producer,
            args=(producer_id,)
        )
        for producer_id in range(producer_count)
    ]

    consumers = [
        threading.Thread(target=consumer)
        for _ in range(consumer_count)
    ]

    for thread in producers:
        thread.start()

    for thread in consumers:
        thread.start()

    for thread in producers:
        thread.join()

    queue.join()

    for thread in consumers:
        thread.join()

    assert len(produced_items) == producer_count * items_per_producer
    assert len(consumed_items) == consumer_count * items_per_producer

    assert sorted(produced_items) == sorted(consumed_items)

if __name__ == "__main__":
    test_basic_push_pop()
    test_multiple_producers_consumers()
    test_multiple_producers_and_consumers()

    print("V2 Thread-Safe Queue Tests: PASS")