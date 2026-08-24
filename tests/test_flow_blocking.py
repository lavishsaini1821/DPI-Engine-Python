from src.connection_tracker import ConnectionTracker
from src.types import FiveTuple, AppType


# Create the connection tracker.
tracker = ConnectionTracker()

# -------------------------------------------------
# TEST 1: Normal flow should remain allowed.
# -------------------------------------------------

normal_flow = FiveTuple(
    src_ip="192.168.1.10",
    dst_ip="8.8.8.8",
    src_port=5000,
    dst_port=443,
    protocol="TCP"
)

flow = tracker.get_or_create_flow(
    normal_flow,
    sni="google.com"
)

print("Normal flow blocked:", flow.blocked)

# -------------------------------------------------
# TEST 2: Blocked source IP should block the flow.
# -------------------------------------------------

blocked_ip_flow = FiveTuple(
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    src_port=5001,
    dst_port=443,
    protocol="TCP"
)

flow = tracker.get_or_create_flow(
    blocked_ip_flow,
    sni="google.com"
)

print("Blocked IP flow:", flow.blocked)

# -------------------------------------------------
# TEST 3: Blocked application should block the flow.
# -------------------------------------------------

blocked_app_flow = FiveTuple(
    src_ip="192.168.1.20",
    dst_ip="31.13.70.1",
    src_port=5002,
    dst_port=443,
    protocol="TCP"
)

flow = tracker.get_or_create_flow(
    blocked_app_flow,
    sni="facebook.com"
)

print("Blocked application flow:", flow.blocked)

# -------------------------------------------------
# TEST 4: Blocked SNI/domain should block the flow.
# -------------------------------------------------

blocked_domain_flow = FiveTuple(
    src_ip="192.168.1.30",
    dst_ip="8.8.8.8",
    src_port=5003,
    dst_port=443,
    protocol="TCP"
)

flow = tracker.get_or_create_flow(
    blocked_domain_flow,
    sni="phishing.com"
)

print("Blocked domain flow:", flow.blocked)

# -------------------------------------------------
# TEST 5: A previously blocked flow must remain blocked.
# -------------------------------------------------

flow_again = tracker.get_or_create_flow(
    blocked_domain_flow,
    sni=None
)
print("Same flow remains blocked:", flow_again.blocked)