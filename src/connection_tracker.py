from src.types import FiveTuple, Flow
from src.rule_manager import RuleManager
class ConnectionTracker:
    """
    Tracks active network flows using their Five-Tuple.
    """
    def __init__(
        self,
        blocked_ips=None,
        blocked_apps=None,
        blocked_domains=None,
    ):
        # Store all active FLOWS using their five-tuple as the key.
        self.flows = {}

        # Create the RuleManager with optional custom blocking rules.
        # Default rules are used when no custom rules are provided.
        self.rule_manager = RuleManager(
            blocked_ips=blocked_ips,
            blocked_apps=blocked_apps,
            blocked_domains=blocked_domains,
        )

    def get_or_create_flow(self, five_tuple: FiveTuple, sni=None) -> Flow:
        """
        Return an existing flow or create a new one.
        """
        # Create the new flow when the five-tuple is seen for the first time
        if five_tuple not in self.flows:
            self.flows[five_tuple] = Flow(
                five_tuple=five_tuple,
                sni = sni 
            )
        flow = self.flows[five_tuple]
        flow.packet_count += 1

        # Store SNI when it becomes available
        if sni and flow.sni is None:
            flow.sni = sni

        # Classify the flow based on its SNI/domain.
        if flow.sni:
            flow.app_type = self.rule_manager.classify_domain(flow.sni)

        # Apply blocking rules to the flow.
        self.apply_blocking_rules(flow)
    
        return flow

    def apply_blocking_rules(self, flow: Flow):
        """
        Apply source IP, application and domain blocking rules.
        """

        # Do not undo a previous blocking decision.
        if flow.blocked:
            return

        # Check whether the source IP is blocked.
        if self.rule_manager.is_ip_blocked(
            flow.five_tuple.src_ip
        ):
            flow.blocked = True
            return

        # Check whether the application is blocked.
        if self.rule_manager.is_app_blocked(
            flow.app_type
        ):
            flow.blocked = True
            return

        # Check whether the SNI/domain is blocked.
        if self.rule_manager.is_domain_blocked(
            flow.sni
        ):
            flow.blocked = True
            return

    def create_five_tuple(self, packet_data):
        """
        Create a five-tuple from parsed packet data.

        Returns None when the packet does not contain
        the fields required for flow tracking.
        """

        src_ip = packet_data.get("src_ip")
        dst_ip = packet_data.get("dst_ip")
        protocol = packet_data.get("protocol")

        if not src_ip or not dst_ip or not protocol:
            return None

        return FiveTuple(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=packet_data.get("src_port", 0),
            dst_port=packet_data.get("dst_port", 0),
            protocol=protocol,
        )

    def get_flow(self, five_tuple: FiveTuple):
        """
        Return a flow if it exists.
        """
        return self.flows.get(five_tuple)

    def get_flow_count(self) -> int:
        """
        Return the number of tracked flows.
        """

        return len(self.flows)