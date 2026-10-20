"""Tests for NetworkEventETL — PySpark transformations."""
import os
import tempfile
from unittest.mock import MagicMock, patch

from src.data_engineering.events import NetworkEvent
from src.data_engineering.pyspark_etl import NetworkEventETL


def _sample_events():
    """Return two sample events for testing."""
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


def test_etl_skips_when_pyspark_missing():
    """If pyspark is not importable, run() should return silently."""
    with patch.dict("sys.modules", {"pyspark.sql": None}):
        etl = NetworkEventETL()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = os.path.join(tmp, "input.parquet")
            output_path = os.path.join(tmp, "output")
            etl.run(input_path, output_path)
            # No ImportError raised — test passes


def test_etl_calls_spark_when_pyspark_available():
    """When pyspark is mocked, verify Spark session and writes happen."""
    mock_spark = MagicMock()
    mock_df = MagicMock()

    # groupBy().agg() returns mock_df so chaining works
    mock_df.groupBy.return_value.agg.return_value = mock_df
    mock_df.orderBy.return_value.limit.return_value = mock_df
    mock_df.filter.return_value.select.return_value.distinct.return_value = mock_df
    mock_df.write.mode.return_value.parquet = MagicMock()

    mock_spark.read.parquet.return_value = mock_df
    mock_spark.builder.appName.return_value.getOrCreate.return_value = mock_spark

    # Replace pyspark.sql module in sys.modules so the in-method
    # `from pyspark.sql import SparkSession` picks up our mocks.
    mock_pyspark_sql = MagicMock()
    mock_pyspark_sql.SparkSession = mock_spark
    mock_pyspark_sql.functions = MagicMock()

    with patch.dict("sys.modules", {"pyspark.sql": mock_pyspark_sql}):
        etl = NetworkEventETL()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = os.path.join(tmp, "input.parquet")
            output_path = os.path.join(tmp, "output")
            etl.run(input_path, output_path)

            # Spark session created with expected app name
            mock_spark.builder.appName.assert_called_with("DPI Network Event ETL")
            mock_spark.read.parquet.assert_called_with(input_path)

            # Four outputs written: app_summary, top_talkers, protocol_dist, blocked_apps
            assert mock_df.write.mode.return_value.parquet.call_count == 4