"""Tests for KafkaSink — publishes NetworkEvent lists to Kafka."""
import os
import sys
import tempfile
from unittest.mock import MagicMock, patch

from src.data_engineering.events import NetworkEvent
from src.data_engineering.kafka_sink import KafkaSink


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


def test_kafka_sink_skips_when_kafka_missing():
    with patch.dict("sys.modules", {"kafka": None}):
        sink = KafkaSink()
        with tempfile.TemporaryDirectory() as tmp:
            sink.publish(_sample_events())


def test_kafka_sink_publishes_json():
    mock_producer = MagicMock()
    mock_producer_class = MagicMock(return_value=mock_producer)

    mock_kafka_module = MagicMock()
    mock_kafka_module.KafkaProducer = mock_producer_class

    with patch.dict("sys.modules", {
        "kafka": mock_kafka_module,
        "kafka.oauth": MagicMock(),
        "kafka.client": MagicMock(),
        "kafka.consumer": MagicMock(),
        "kafka.consumer.fetcher": MagicMock(),
        "kafka.consumer.group": MagicMock(),
        "kafka.consumer.subscription_state": MagicMock(),
        "kafka.producer": MagicMock(),
        "kafka.producer.record_accumulator": MagicMock(),
        "kafka.producer.sender": MagicMock(),
        "kafka.partitioner": MagicMock(),
        "kafka.protocol": MagicMock(),
    }):
        sink = KafkaSink()
        with tempfile.TemporaryDirectory() as tmp:
            sink.publish(_sample_events(), topic="test_topic")
            mock_producer_class.assert_called_once()
            call_kwargs = mock_producer_class.call_args.kwargs
            assert call_kwargs["bootstrap_servers"] == "localhost:9092"
            assert callable(call_kwargs["value_serializer"])
            mock_producer.send.assert_called()
            mock_producer.flush.assert_called_once()
            mock_producer.close.assert_called_once()
