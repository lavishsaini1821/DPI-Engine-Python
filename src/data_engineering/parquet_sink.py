"""
Write NetworkEvent objects to a Parquet file.

Parquet is a columnar format. It is the standard input for
PySpark, pandas, DuckDB, and most analytical tools.
"""
from typing import List

from src.data_engineering.events import NetworkEvent


class ParquetSink:
    """Persists NetworkEvent lists as a Parquet file."""

    def write(self, events: List[NetworkEvent], path: str) -> None:
        """Write events to a single Parquet file at `path`."""
        # Imports are kept inside the method so the DE layer is a
        # soft dependency. If pyarrow is not installed, importing
        # this module still works; only `write()` fails.
        import pyarrow as pa
        import pyarrow.parquet as pq

        # Build a column-oriented table from the list of dataclasses.
        # pa.table(rows) infers the schema from the first row.
        table = pa.table(
            {
                "src_ip": [e.src_ip for e in events],
                "dst_ip": [e.dst_ip for e in events],
                "src_port": [e.src_port for e in events],
                "dst_port": [e.dst_port for e in events],
                "protocol": [e.protocol for e in events],
                "packet_length": [e.packet_length for e in events],
                "sni": [e.sni for e in events],
                "http_host": [e.http_host for e in events],
                "http_method": [e.http_method for e in events],
                "http_path": [e.http_path for e in events],
                "user_agent": [e.user_agent for e in events],
                "application": [e.application for e in events],
                "decision": [e.decision for e in events],
                "blocked": [e.blocked for e in events],
                "flow_packet_count": [e.flow_packet_count for e in events],
            }
        )

        pq.write_table(table, path)
