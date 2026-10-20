"""Tests for PostgresSink — writes NetworkEvent lists to PostgreSQL."""
import os
import tempfile
from unittest.mock import MagicMock, patch

from src.data_engineering.events import NetworkEvent
from src.data_engineering.postgres_sink import PostgresSink


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


def test_postgres_sink_skips_when_psycopg2_missing():
    with patch.dict("sys.modules", {"psycopg2": None}):
        sink = PostgresSink()
        with tempfile.TemporaryDirectory() as tmp:
            sink.write(_sample_events(), "postgresql://localhost/dpi")


def test_postgres_sink_writes_rows():
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur
    mock_conn.cursor.return_value.__exit__.return_value = None

    mock_psycopg2 = MagicMock()
    mock_psycopg2.connect.return_value = mock_conn

    with patch.dict("sys.modules", {"psycopg2": mock_psycopg2}):
        sink = PostgresSink()
        with tempfile.TemporaryDirectory() as tmp:
            sink.write(_sample_events(), "postgresql://localhost/dpi")
            # execute called for CREATE TABLE; executemany for INSERT
            assert mock_cur.execute.call_count >= 1
            assert mock_cur.executemany.called
            mock_conn.commit.assert_called_once()
            mock_conn.close.assert_called_once()
