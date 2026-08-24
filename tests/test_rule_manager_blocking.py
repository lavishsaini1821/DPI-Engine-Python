from src.rule_manager import RuleManager
from src.types import AppType

# Create the RuleManager.
rules = RuleManager()

# Test source IP blocking.
print("IP blocked:",
      rules.is_ip_blocked("192.168.1.100"))

print("IP allowed:",
      rules.is_ip_blocked("192.168.1.10"))

# Test application blocking.
print("Facebook blocked:",
      rules.is_app_blocked(AppType.FACEBOOK))

print("YouTube blocked:",
      rules.is_app_blocked(AppType.YOUTUBE))

# Test domain blocking.
print("Domain blocked:",
      rules.is_domain_blocked("phishing.com"))

print("Domain allowed:",
      rules.is_domain_blocked("google.com"))