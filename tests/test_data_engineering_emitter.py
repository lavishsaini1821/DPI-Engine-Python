"""Tests for NetworkEventEmitter — converts DPI output to events."""
from src.connection_tracker import ConnectionTracker
from src.dpi_engine import DPIEngine
from src.pcap_reader import PcapReader
from src.data_engineering.emitter import NetworkEventEmitter


def _run_dpi():
    """Helper: run V1 DPI on the test PCAP and return the tuple."""
    reader = PcapReader("input/test_dpi.pcap")
    packets = reader.read_packets()
    engine = DPIEngine()
    return engine.process_packets(packets), engine


def test_emitter_produces_one_event_per_packet():
    (parsed, _stats, decisions, _fwd), _ = _run_dpi()
    emitter = NetworkEventEmitter(parsed, decisions, _run_dpi()[1].connection_tracker)
    events = emitter.emit_all()
    assert len(events) == len(parsed) == 77


def test_event_enriches_packet_with_flow_data():
    (parsed, _stats, decisions, _fwd), engine = _run_dpi()
    emitter = NetworkEventEmitter(parsed, decisions, engine.connection_tracker)
    events = emitter.emit_all()

    # At least one event must carry an SNI and a known application.
    sni_events = [e for e in events if e.sni]
    assert len(sni_events) > 0
    assert sni_events[0].application in {
        "GOOGLE", "YOUTUBE", "FACEBOOK", "GITHUB", "AMAZON",
        "INSTAGRAM", "TWITTER", "NETFLIX", "DISCORD", "ZOOM",
        "TELEGRAM", "TIKTOK", "SPOTIFY", "CLOUDFLARE",
        "MICROSOFT", "APPLE",
    }


def test_blocked_packet_appears_as_dropped():
    (parsed, _stats, decisions, _fwd), engine = _run_dpi()
    emitter = NetworkEventEmitter(parsed, decisions, engine.connection_tracker)
    events = emitter.emit_all()

    drop_events = [e for e in events if e.decision == "DROP"]
    assert len(drop_events) == 1
    assert drop_events[0].application == "FACEBOOK"
    assert drop_events[0].blocked is True


if __name__ == "__main__":
    test_emitter_produces_one_event_per_packet()
    test_event_enriches_packet_with_flow_data()
    test_blocked_packet_appears_as_dropped()
    print("NetworkEventEmitter tests: PASS")
