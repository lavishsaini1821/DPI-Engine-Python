from queue import Queue
from typing import Generic, TypeVar

T = TypeVar("T")

class ThreadSafeQueue(Generic[T]):
    """
    Thread-safe producer/consumer queue used by the V2
    multi-threaded DPI pipeline.
    """

    def __init__(self, maxsize: int = 0):
        self._queue: Queue[T] = Queue(maxsize=maxsize)

    def push(self, item: T) -> None:
        """Add an item to the queue."""
        self._queue.put(item)

    def pop(self, timeout: float | None = None) -> T:
        """Remove and return an item from the queue."""
        return self._queue.get(timeout=timeout)

    def task_done(self) -> None:
        """Mark a previously retrieved item as processed."""
        self._queue.task_done()

    def join(self) -> None:
        """Wait until all queued tasks have been processed."""
        self._queue.join()

    def empty(self) -> bool:
        """Return True if the queue is empty."""
        return self._queue.empty()

    def size(self) -> int:
        """Return the current approximate queue size."""
        return self._queue.qsize()
