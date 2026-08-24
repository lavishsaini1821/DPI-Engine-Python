from src.connection_tracker import ConnectionTracker
from src.types import FiveTuple


# Create the connection tracker.
tracker = ConnectionTracker()


# -------------------------------------------------
# TEST 1: Allowed domain
# -------------------------------------------------

allowed_flow_tuple = FiveTuple(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=5000,
    dst_port=443,
    protocol="TCP"
)

allowed_flow = tracker.get_or_create_flow(
    allowed_flow_tuple,
    sni="google.com"
)

print("Allowed domain:")
print("SNI:", allowed_flow.sni)
print("Application:", allowed_flow.app_type.value)
print("Blocked:", allowed_flow.blocked)


# -------------------------------------------------
# TEST 2: Blocked application
# -------------------------------------------------

blocked_app_tuple = FiveTuple(
    src_ip="192.168.1.20",
    dst_ip="31.13.70.1",
    src_port=5001,
    dst_port=443,
    protocol="TCP"
)

blocked_app_flow = tracker.get_or_create_flow(
    blocked_app_tuple,
    sni="facebook.com"
)

print("\nBlocked application:")
print("SNI:", blocked_app_flow.sni)
print("Application:", blocked_app_flow.app_type.value)
print("Blocked:", blocked_app_flow.blocked)


# -------------------------------------------------
# TEST 3: Blocked domain
# -------------------------------------------------

blocked_domain_tuple = FiveTuple(
    src_ip="192.168.1.30",
    dst_ip="8.8.8.8",
    src_port=5002,
    dst_port=443,
    protocol="TCP"
)

blocked_domain_flow = tracker.get_or_create_flow(
    blocked_domain_tuple,
    sni="phishing.com"
)

print("\nBlocked domain:")
print("SNI:", blocked_domain_flow.sni)
print("Application:", blocked_domain_flow.app_type.value)
print("Blocked:", blocked_domain_flow.blocked)