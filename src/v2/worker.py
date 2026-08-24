import threading
from typing import Callable, Generic, TypeVar
from src.v2.thread_safe_queue import ThreadSafeQueue

T = TypeVar("T")

class DPIWorker(Generic[T]):
    """
    Background worker that consumes items from a
    thread-safe queue and processes them.
    """

    def __init__(self,worker_id: int,queue: ThreadSafeQueue[T],processor: Callable[[T], None],):
        self.worker_id = worker_id
        self.queue = queue
        self.processor = processor
        self._stop_event = threading.Event()
        self._processed_count = 0
        self._error_count = 0
        self._last_error = None
        self._results = []
        self._thread = threading.Thread(target=self._run,name=f"dpi-worker-{worker_id}",)

    def start(self) -> None:
        """Start the worker thread."""
        self._thread.start()

    def stop(self) -> None:
        """Request the worker to stop."""
        self._stop_event.set()

    def join(self) -> None:
        """Wait for the worker thread to finish."""
        self._thread.join()

    @property
    def processed_count(self) -> int:
        """Return the number of successfully processed items."""
        return self._processed_count         

    def _run(self) -> None:
        """Worker loop."""

        while not self._stop_event.is_set():

            try:
                item = self.queue.pop(timeout=0.1)

            except Exception:
                continue

            try:
                result = self.processor(item)
                self._results.append(result)
                self._processed_count += 1

            except Exception as error:
                # One malformed packet must not kill the thread. If it
                # did, this worker's queue would never drain again and
                # WorkerPool.wait_until_empty() would block forever.
                self._error_count += 1
                self._last_error = error

            finally:
                self.queue.task_done()

    @property
    def error_count(self) -> int:
        """Return the number of items that failed to process."""
        return self._error_count

    @property
    def last_error(self) -> Exception | None:
        """Return the most recent processing error, if any."""
        return self._last_error

    @property
    def results(self) -> list:
        """Return the results produced by this worker."""
        return self._results