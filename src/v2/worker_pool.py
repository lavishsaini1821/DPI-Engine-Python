from typing import Callable, Generic, TypeVar
from src.v2.flow_balancer import FlowBalancer, FlowKey
from src.v2.thread_safe_queue import ThreadSafeQueue
from src.v2.worker import DPIWorker

T = TypeVar("T")

class WorkerPool(Generic[T]):
    """
    Manages worker queues and DPI worker threads.
    Each network flow is assigned to one worker using
    five-tuple hashing.
    """
    def __init__(
        self,
        worker_count: int,
        processor: Callable[[T], None] | None = None,
        processor_factory: Callable[[], Callable[[T], None]] | None = None,
    ):

        if worker_count <= 0:
            raise ValueError("worker_count must be greater than zero")

        if processor is None and processor_factory is None:
            raise ValueError(
                "provide either processor or processor_factory"
            )

        self.worker_count = worker_count
        self.balancer = FlowBalancer(worker_count)
        self.queues = [
            ThreadSafeQueue[T]()
            for _ in range(worker_count)
        ]

        # Give every worker its own processor when a factory is
        # supplied. Flow-hash affinity guarantees a flow always
        # reaches the same worker, so per-worker state needs no lock.
        # Sharing one processor across threads would race on its
        # flow table and defeat the whole point of the affinity.
        if processor_factory is not None:
            self.processors = [
                processor_factory()
                for _ in range(worker_count)
            ]
        else:
            self.processors = [processor] * worker_count

        self.workers = [
            DPIWorker(
                worker_id=worker_id,
                queue=self.queues[worker_id],
                processor=self.processors[worker_id],
            )
            for worker_id in range(worker_count)
        ]

    def start(self) -> None:
        """Start all worker threads."""

        for worker in self.workers:
            worker.start()

    def stop(self) -> None:
        """Stop all worker threads."""

        for worker in self.workers:
            worker.stop()

    def join(self) -> None:
        """Wait for all worker threads to finish."""

        for worker in self.workers:
            worker.join()

    def submit(self, flow: FlowKey, item: T) -> int:
        """
        Assign an item to the worker responsible for the flow.
        Returns the selected worker ID.
        """
        worker_id = self.balancer.get_worker(flow)
        self.queues[worker_id].push(item)

        return worker_id

    def wait_until_empty(self) -> None:
        """
        Wait until all worker queues have processed their items.
        """
        for queue in self.queues:
            queue.join()

    def get_queue(self,worker_id: int,) -> ThreadSafeQueue[T]: 

        if worker_id < 0 or worker_id >= self.worker_count:
            raise ValueError("invalid worker_id")

        return self.queues[worker_id]

    def get_worker_stats(self) -> dict[int, int]:
        """
        Return the number of processed items for each worker.
        """
        return {
            worker.worker_id: worker.processed_count
            for worker in self.workers
        }

    def get_error_stats(self) -> dict[int, int]:
        """
        Return the number of failed items for each worker.
        Only workers that actually saw an error are included.
        """
        return {
            worker.worker_id: worker.error_count
            for worker in self.workers
            if worker.error_count
        }

    def get_results(self) -> list:
        """
        Return all processing results from the workers.
        """

        results = []

        for worker in self.workers:
            results.extend(worker.results)

        return results