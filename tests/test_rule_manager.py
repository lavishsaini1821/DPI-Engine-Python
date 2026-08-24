from src.rule_manager import RuleManager
from src.types import AppType


rule_manager = RuleManager()


test_domains = [
    "youtube.com",
    "www.youtube.com",
    "google.com",
    "github.com",
    "Amazon.com",
    "unknown-site.com"
]


for domain in test_domains:
    result = rule_manager.classify_domain(domain)

    print(f"{domain} -> {result.value}")