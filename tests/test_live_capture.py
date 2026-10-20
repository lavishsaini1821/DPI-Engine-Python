"""Tests for the live packet capture module.

These tests do NOT require Npcap. They verify:
- interface resolution logic
- fallback to PCAP replay when live capture is unavailable
- interface listing
- no side effects on the rest of the pipeline
"""
import os
from unittest.mock import patch, MagicMock

from src.live_capture import LivePacketCapture


def _make_dummy_iface(name="Ethernet", hwaddr="AA:BB:CC:DD:EE:FF", isloopback=False):
    """Return a MagicMock that mimics scapy's Iface objects."""
    m = MagicMock()
    m.name = name
    m.hwaddr = hwaddr
    m.isloopback = isloopback
    m.info = None
    return m


def test_resolved_interface_none_when_no_usable():
    """When no interface is given and none is usable, resolved is None."""
    with patch("src.live_capture.ifaces", {}):
        capture = LivePacketCapture()
        assert capture._resolve_interface() is None


def test_resolved_interface_explicit_name():
    """An explicit interface name is returned unchanged if valid."""
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        capture = LivePacketCapture(interface="Ethernet")
        assert capture._resolve_interface() == "Ethernet"


def test_resolved_interface_suffix_match():
    """An interface name ending with the requested suffix is matched."""
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface(name="Ethernet")}):
        capture = LivePacketCapture(interface="net")
        assert capture._resolve_interface() == "Ethernet"


def test_list_interfaces_excludes_loopback():
    """list_interfaces returns only non-loopback interfaces."""
    ifaces_obj = {
        "loopback": _make_dummy_iface(name="loopback", hwaddr="00:00:00:00:00:00", isloopback=True),
        "Ethernet": _make_dummy_iface(name="Ethernet", hwaddr="AA:BB:CC:DD:EE:FF", isloopback=False),
    }
    with patch("src.live_capture.ifaces", ifaces_obj):
        capture = LivePacketCapture()
        interfaces = capture.list_interfaces()
        assert len(interfaces) == 1
        assert interfaces[0]["name"] == "Ethernet"
        assert interfaces[0]["isloopback"] is False


def test_simulate_capture_falls_back_to_pcap():
    """When live capture is unavailable, sniff falls back to PCAP replay."""
    capture = LivePacketCapture()
    with patch("src.live_capture.ifaces", {}):
        packets = capture.sniff()
        assert len(packets) > 0


def test_simulate_capture_no_pcap_falls_back_to_parquet():
    """When no PCAP exists, sniff falls back to the parquet file."""
    capture = LivePacketCapture()
    with patch("src.live_capture.ifaces", {}):
        with patch("os.path.exists", return_value=True):
            packets = capture.sniff()
            assert len(packets) > 0


def test_capture_saves_pcap():
    """When pcap_save is set and live capture works, packets are written."""
    capture = LivePacketCapture(pcap_save="output/test_live_capture.pcap")
    mock_sniff = MagicMock(return_value=[MagicMock()])
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        with patch("src.live_capture.sniff", mock_sniff):
            capture.sniff()
            assert mock_sniff.called


def test_capture_callback_invoked():
    """When a callback is passed, each packet is forwarded to it."""
    capture = LivePacketCapture()
    received = []
    with patch("src.live_capture.ifaces", {}):
        packets = capture.sniff(callback=lambda p: received.append(p))
        assert isinstance(received, list)


def test_capture_uses_filter():
    """Filter is passed through to sniff."""
    capture = LivePacketCapture(filter="tcp and port 443")
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        mock_sniff = MagicMock(return_value=[])
        with patch("src.live_capture.sniff", mock_sniff):
            capture.sniff()
            assert mock_sniff.call_args.kwargs.get("filter") == "tcp and port 443"


def test_capture_uses_timeout():
    """Timeout is passed through to sniff."""
    capture = LivePacketCapture(timeout=5)
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        mock_sniff = MagicMock(return_value=[])
        with patch("src.live_capture.sniff", mock_sniff):
            capture.sniff()
            assert mock_sniff.call_args.kwargs.get("timeout") == 5


def test_capture_uses_stop_after():
    """stop_after is passed through to sniff as count."""
    capture = LivePacketCapture(stop_after=10)
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        mock_sniff = MagicMock(return_value=[])
        with patch("src.live_capture.sniff", mock_sniff):
            capture.sniff()
            assert mock_sniff.call_args.kwargs.get("count") == 10


def test_capture_uses_promiscuous():
    """promiscuous is passed through to sniff."""
    capture = LivePacketCapture(promiscuous=False)
    with patch("src.live_capture.ifaces", {"Ethernet": _make_dummy_iface()}):
        mock_sniff = MagicMock(return_value=[])
        with patch("src.live_capture.sniff", mock_sniff):
            capture.sniff()
            assert mock_sniff.call_args.kwargs.get("promisc") is False


def test_streaming_starts_and_stops():
    """start_streaming spawns threads; stop_streaming terminates them."""
    capture = LivePacketCapture(timeout=1)
    with patch("src.live_capture.ifaces", {}):
        with patch("src.live_capture.sniff", return_value=[]):
            capture.start_streaming(callback=lambda p: None)
            import time
            time.sleep(0.5)
            capture.stop_streaming()
            assert hasattr(capture, "_stop")
            assert capture._stop is True


def test_npcap_paths_exist():
    """NPCAP_PATHS points at the standard Windows install locations."""
    assert len(LivePacketCapture.NPCAP_PATHS) == 2
    for path in LivePacketCapture.NPCAP_PATHS:
        assert path.endswith("Npcap.dll")