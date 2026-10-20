"""Tests for ParquetSink — writes NetworkEvent lists to a Parquet file."""
import os
import tempfile

import pyarrow.parquet as pq

from src.data_engineering.events import NetworkEvent
from src.data_engineering.parquet_sink import ParquetSink


def _sample_events():
    return [
        NetworkEvent(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            src_port=1234, dst_port=443,
            protocol="TCP", packet_length=100,
            sni="example.com", http_host=None,
            http_method=None, http_path=None, user_agent=None,
            application="GOOGLE", decision="FORWARD",
            blocked=False, flow_packet_count=1,
        ),
        NetworkEvent(
            src_ip="3.3.3.3", dst_ip="4.4.4.4",
            src_port=5555, dst_port=443,
            protocol="TCP", packet_length=200,
            sni="facebook.com", http_host=None,
            http_method=None, http_path=None, user_agent=None,
            application="FACEBOOK", decision="DROP",
            blocked=True, flow_packet_count=3,
        ),
    ]


def test_parquet_sink_writes_readable_file():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "events.parquet")
        ParquetSink().write(_sample_events(), path)
        assert os.path.exists(path)

        table = pq.read_table(path)
        assert table.num_rows == 2
        assert "sni" in table.column_names
        assert "decision" in table.column_names


def test_parquet_sink_preserves_values():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "events.parquet")
        ParquetSink().write(_sample_events(), path)
        table = pq.read_table(path)

        snis = table.column("sni").to_pylist()
        decisions = table.column("decision").to_pylist()
        apps = table.column("application").to_pylist()

        assert "example.com" in snis
        assert "facebook.com" in snis
        assert "FORWARD" in decisions
        assert "DROP" in decisions
        assert "FACEBOOK" in apps


if __name__ == "__main__":
    test_parquet_sink_writes_readable_file()
    test_parquet_sink_preserves_values()
    print("ParquetSink tests: PASS")
