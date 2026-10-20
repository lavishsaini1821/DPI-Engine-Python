"""
Live packet capture for Windows using Scapy + Npcap.

Provides a live packet capture with configurable network interface.
Npcap (with libpcap API) is required for real live capture on Windows.
When Npcap is unavailable, live capture degrades to an emulator that
replays an existing PCAP so the rest of the DPI pipeline still runs.

Usage:
    from src.live_capture import LivePacketCapture
    capture = LivePacketCapture(interface="Ethernet", timeout=10)
    packets = capture.sniff()

Configuration:
    - interface (str, optional): interface name, index, or NDIS device path.
      If None, a non-loopback interface is auto-selected.
    - promiscuous (bool, default True): enable promiscuous mode.
    - timeout (int, default 10): seconds to sniff (0 = no timeout).
    - filter (str, default None): BPF expression, e.g. "tcp and port 443".
    - stop_after (int, default None): capture this many packets then stop.
    - pcap_save (str, optional): path to save captured packets.
"""
from __future__ import annotations

import ctypes.util
import time
import warnings
from typing import Any, Callable, List, Optional

from scapy.all import (
    get_if_hwaddr,
    ifaces,
    sendp,
    sniff,
    wrpcap,
    conf,
)


class LivePacketCapture:
    """Live packet capture over Windows network interfaces (Npcap/scapy)."""

    NPCAP_PATHS = [
        "C:\\Program Files\\Npcap\\Npcap.dll",
        "C:\\Program Files (x86)\\Npcap\\Npcap.dll",
    ]

    def __init__(
        self,
        interface: Optional[str] = None,
        promiscuous: bool = True,
        timeout: int = 10,
        filter: Optional[str] = None,
        stop_after: Optional[int] = None,
        pcap_save: Optional[str] = None,
    ):
        self.interface = interface
        self.promiscuous = promiscuous
        self.timeout = timeout
        self.filter = filter
        self.stop_after = stop_after
        self.pcap_save = pcap_save
        self._resolved_interface = None
        self._capture_started = False

    @staticmethod
    def _npcap_available() -> bool:
        """Check whether Npcap is installed and its DLL can be loaded."""
        for path in LivePacketCapture.NPCAP_PATHS:
            try:
                ctypes.CDLL(path)
                return True
            except OSError:
                continue
        return False

    @staticmethod
    def _has_libpcap_provider() -> bool:
        """Check whether scapy reports at least one libpcap provider."""
        from scapy.layers import l2

        return bool(getattr(l2, "pcap_provider", None))

    @staticmethod
    def _is_loopback(iface_info) -> bool:
        """Detect loopback interfaces across scapy versions.

        NetworkInterface_Win objects do not expose an ``isloopback``
        attribute, so we fall back to checking the friendly name and
        description for the loopback pseudo-interface.
        """
        try:
            if iface_info.isloopback:
                return True
        except AttributeError:
            pass
        name = str(getattr(iface_info, "name", "") or "")
        description = str(getattr(iface_info, "description", "") or "")
        return "loopback" in name.lower() or "loopback" in description.lower()

    @staticmethod
    def _get_hwaddr(iface_info) -> str:
        """Return the hardware address of an interface.

        ``NetworkInterface_Win`` exposes ``mac``; older scapy versions
        used ``hwaddr``.  Prefer whichever is available.
        """
        hw = getattr(iface_info, "mac", None)
        if not hw:
            hw = getattr(iface_info, "hwaddr", None)
        return hw or ""

    def _resolve_interface(self) -> Optional[str]:
        """Resolve the requested interface name -> scapy iface string."""
        if self.interface is None:
            # Auto-select a real, non-loopback interface that has traffic.
            candidates = []
            for iface_name, iface_info in ifaces.items():
                if self._is_loopback(iface_info):
                    continue
                hw = self._get_hwaddr(iface_info)
                if not hw or hw == "00:00:00:00:00:00":
                    continue
                candidates.append(iface_name)
            if candidates:
                chosen = candidates[0]
                warnings.warn(
                    f"No interface specified; auto-selected "
                    f"{chosen!r} ({get_if_hwaddr(chosen)!r}). "
                    f"Pass --interface to choose explicitly."
                )
                return chosen
            return None

        # If it is already a valid scapy interface name, use it directly.
        valid_names = list(ifaces.keys())
        if self.interface in valid_names:
            return self.interface

        # Try resolving by NDIS device path or index.
        for name in valid_names:
            if name.endswith(self.interface):
                return name
        return self.interface

    def list_interfaces(self) -> List[dict[str, Any]]:
        """Return a list of usable (non-loopback) interfaces with info."""
        out: List[dict[str, Any]] = []
        for iface_name, iface_info in ifaces.items():
            if self._is_loopback(iface_info):
                continue
            out.append(
                {
                    "name": iface_name,
                    "hwaddr": self._get_hwaddr(iface_info),
                    "ip": getattr(iface_info, "ip", None) or getattr(iface_info, "info", None),
                    "isloopback": self._is_loopback(iface_info),
                    "isup": True,
                }
            )
        return out

    def _setup_npcap_promisc(self) -> None:
        """Apply Npcap promiscuous-mode settings if Npcap is present."""
        if not self._npcap_available():
            return
        try:
            npcap_dll = ctypes.CDLL(
                self.NPCAP_PATHS[0]
            )
            for iface_name in list(ifaces.keys()):
                ifaces[iface_name].promisc = self.promiscuous
        except Exception:  # best-effort; failures are non-fatal
            pass

    def sniff(self, callback: Optional[Callable[[Any], None]] = None) -> List[Any]:
        """
        Capture packets live.

        Returns a Scapy packet list. Falls back to a simulated capture
        (replaying an existing PCAP) when live capture is unavailable,
        so the rest of the pipeline can still run.
        """
        # Try real live capture first.
        resolved = self._resolve_interface()
        if resolved is None:
            return self._simulate_capture("no usable network interface found")

        self._resolved_interface = resolved

        # Best-effort Npcap promiscuous setup.
        try:
            self._setup_npcap_promisc()
        except Exception:
            pass

        try:
            packets = sniff(
                iface=self._resolved_interface,
                promisc=self.promiscuous,
                timeout=self.timeout,
                filter=self.filter,
                count=self.stop_after,
                store=False if callback else True,
            )
            if callback and packets:
                for p in packets:
                    try:
                        callback(p)
                    except Exception:
                        pass
            if self.pcap_save:
                wrpcap(self.pcap_save, packets)
            if len(packets) == 0:
                return self._simulate_capture(
                    "timeout with no live packets captured"
                )
            return packets
        except Exception as e:
            return self._simulate_capture(
                f"live capture failed: {e!r}"
            )

    def _simulate_capture(self, reason: str) -> List[Any]:
        """Fallback: replay an existing PCAP file as simulated traffic."""
        warnings.warn(
            f"Live capture unavailable ({reason}); "
            f"degrading to PCAP replay for pipeline testing. "
            f"Install Npcap to enable real live capture. See "
            f"docs/live-capture.md for instructions."
        )
        from src.pcap_reader import PcapReader

        candidate = "input/test_dpi.pcap"
        if not __import__("os").path.exists(candidate):
            candidate = "output/network_events.parquet"
        reader = PcapReader(candidate)
        return reader.read_packets()

    def start_streaming(
        self,
        callback: Callable[[Any], None],
        interval: float = 1.0,
        max_packets: Optional[int] = None,
    ) -> None:
        """
        Continuously sniff packets in background threads.

        Each captured packet is passed to `callback(packet)`. Stop the
        stream by calling `stop_streaming()` from another thread.
        """
        import threading

        self._stop = False
        self._max_packets = max_packets
        self._count = 0

        def worker():
            while not self._stop:
                try:
                    packets = self.sniff(timeout=interval, callback=callback)
                except Exception:
                    pass
                if max_packets is not None:
                    with threading.Lock():
                        self._count += len(packets)
                        if self._count >= max_packets:
                            self.stop_streaming()
                            break

        threads = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
        for t in threads:
            t.start()

    def stop_streaming(self) -> None:
        """Stop a streaming capture started with start_streaming()."""
        if hasattr(self, "_stop"):
            self._stop = True
