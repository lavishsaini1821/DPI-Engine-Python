from src.rule_manager import RuleManager
from src.types import AppType


rule_manager = RuleManager()


print("========== DAY 18 DOMAIN MATCHING ==========")

tests = [
    ("youtube.com", AppType.YOUTUBE),
    ("www.youtube.com", AppType.YOUTUBE),
    ("m.youtube.com", AppType.YOUTUBE),
    ("gaming.youtube.com", AppType.YOUTUBE),
    ("notyoutube.com", AppType.UNKNOWN),
]


all_passed = True

for domain, expected in tests:
    result = rule_manager.classify_domain(domain)

    passed = result == expected

    print(
        f"{domain} -> {result.name} | "
        f"Expected: {expected.name} | "
        f"{'PASS' if passed else 'FAIL'}"
    )

    if not passed:
        all_passed = False


print("\nBlocking tests:")

blocking_tests = [
    ("phishing.com", True),
    ("login.phishing.com", True),
    ("secure.login.phishing.com", True),
    ("notphishing.com", False),
]


for domain, expected in blocking_tests:
    result = rule_manager.is_domain_blocked(domain)

    passed = result == expected

    print(
        f"{domain} -> Blocked: {result} | "
        f"Expected: {expected} | "
        f"{'PASS' if passed else 'FAIL'}"
    )

    if not passed:
        all_passed = False


print("\nLabel rule tests:")

# A rule without a dot is matched label by label.
label_rules = RuleManager(blocked_domains={"facebook"})

label_tests = [
    ("www.facebook.com", True),
    ("facebook.co.uk", True),
    ("facebook", True),
    ("notfacebook.com", False),
    ("facebooking.com", False),
]


for domain, expected in label_tests:
    result = label_rules.is_domain_blocked(domain)

    passed = result == expected

    print(
        f"{domain} -> Blocked: {result} | "
        f"Expected: {expected} | "
        f"{'PASS' if passed else 'FAIL'}"
    )

    if not passed:
        all_passed = False


print("\nVerification:")

if all_passed:
    print("Domain matching: PASS")
else:
    print("Domain matching: FAIL")

assert all_passed

assert all_passed