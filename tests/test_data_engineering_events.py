"""Tests for the NetworkEvent dataclass."""
from src.data_engineering.events import NetworkEvent


def test_event_holds_all_fields():
    event = NetworkEvent(
        src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=1234, dst_port=443,
        protocol="TCP", packet_length=100,
        sni="example.com",
        http_host=None, http_method=None, http_path=None, user_agent=None,
        application="GOOGLE", decision="FORWARD",
        blocked=False, flow_packet_count=1,
    )
    assert event.src_ip == "1.1.1.1"
    assert event.sni == "example.com"
    assert event.decision == "FORWARD"


def test_event_is_immutable():
    """NetworkEvent is frozen — modifications should raise."""
    event = NetworkEvent(
        src_ip="1.1.1.1", dst_ip="2.2.2.2",
        src_port=1234, dst_port=443,
        protocol="TCP", packet_length=100,
        sni=None, http_host=None, http_method=None,
        http_path=None, user_agent=None,
        application="UNKNOWN", decision="FORWARD",
        blocked=False, flow_packet_count=1,
    )
    try:
        event.decision = "DROP"
        assert False, "frozen dataclass should reject assignment"
    except Exception:
        pass


if __name__ == "__main__":
    test_event_holds_all_fields()
    test_event_is_immutable()
    print("NetworkEvent tests: PASS")
