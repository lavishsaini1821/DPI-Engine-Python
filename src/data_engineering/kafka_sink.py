"""
Phase 4: Kafka sink for NetworkEvent records.

Publishes each event as a JSON message on a Kafka topic.
Soft dependency: kafka-python is imported inside publish(),
so the DPI pipeline still works if Kafka is not configured.
"""

import json

try:
    from kafka.serializer import Serializer
except ImportError:
    Serializer = object


class _JsonValueSerializer(Serializer):
    """Serializer for JSON-encoded NetworkEvent values."""

    def __init__(self):
        pass

    def serialize(self, value, **kwargs):
        return json.dumps(value).encode("utf-8")


class KafkaSink:
    """Publishes NetworkEvent lists to a Kafka topic."""

    def publish(self, events, topic: str = "network_events",
                bootstrap_servers: str = "localhost:9092") -> bool:
        """
        Publish events to Kafka as JSON messages.

        Args:
            events: List of NetworkEvent dataclasses.
            topic: Kafka topic name.
            bootstrap_servers: Kafka broker list, e.g.
                "kafka1:9092,kafka2:9092".
        """
        try:
            from kafka import KafkaProducer
        except ImportError:
            print("\nKafkaSink skipped — kafka-python not installed.")
            return False

        if not events:
            print("\nKafkaSink: no events to publish.")
            return False

        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=_JsonValueSerializer().serialize,
            )
        except Exception as exc:
            print(f"\nKafkaSink skipped: {exc}. (Need Kafka broker running.)")
            return False

        try:
            for event in events:
                message = {
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                    "src_port": event.src_port,
                    "dst_port": event.dst_port,
                    "protocol": event.protocol,
                    "packet_length": event.packet_length,
                    "sni": event.sni,
                    "http_host": event.http_host,
                    "http_method": event.http_method,
                    "http_path": event.http_path,
                    "user_agent": event.user_agent,
                    "application": event.application,
                    "decision": event.decision,
                    "blocked": event.blocked,
                    "flow_packet_count": event.flow_packet_count,
                }
                producer.send(topic, value=message)
            producer.flush()
            print(f"\nKafkaSink: {len(events)} events published to '{topic}'.")
            return True
        finally:
            producer.close()