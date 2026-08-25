from src.types import AppType

class RuleManager:
    """
    Classifies network traffic based on domain/SNI rules.
    """

    def __init__(
        self,
        blocked_ips=None,
        blocked_apps=None,
        blocked_domains=None,
    ):

        # Store domain-to-application classification rules.
        self.domain_rules = {
            # Search / productivity
            "google.com": AppType.GOOGLE,

            # Social media
            "facebook.com": AppType.FACEBOOK,

            # Video / entertainment
            "youtube.com": AppType.YOUTUBE,

            # Development
            "github.com": AppType.GITHUB,

            # Additional applications
            "instagram.com": AppType.INSTAGRAM,
            "twitter.com": AppType.TWITTER,
            "amazon.com": AppType.AMAZON,
            "netflix.com": AppType.NETFLIX,
            "discord.com": AppType.DISCORD,
            "zoom.us": AppType.ZOOM,
            "telegram.org": AppType.TELEGRAM,
            "tiktok.com": AppType.TIKTOK,
            "spotify.com": AppType.SPOTIFY,
            "cloudflare.com": AppType.CLOUDFLARE,
            "microsoft.com": AppType.MICROSOFT,
            "apple.com": AppType.APPLE,
        }

        # Use custom blocked IP addresses when provided.
        # Otherwise, use the default blocked IP list.
        self.blocked_ips = (
            set(blocked_ips)
            if blocked_ips is not None
            else {"10.0.0.50"}
        )

        # Use custom blocked applications when provided.
        #   Otherwise, block Facebook by default.
        self.blocked_apps = (
            set(blocked_apps)
            if blocked_apps is not None
            else {AppType.FACEBOOK}
        )

        # Use custom blocked domains when provided.
        # Otherwise, use the default suspicious-domain list.
        self.blocked_domains = (
            set(blocked_domains)
            if blocked_domains is not None
            else {
                "malicious.com",
                "phishing.com",
                "evil-site.net",
                "fake-login.com",
            }
        )

    def classify_domain(self, domain):
        """
        Return the application type for a given domain.

        Exact domains and valid subdomains are supported.
        """

        if not domain:
            return AppType.UNKNOWN

        domain = domain.lower().strip().rstrip(".")

        for rule_domain, app_type in self.domain_rules.items():

            rule_domain = (rule_domain.lower().strip().rstrip("."))

            if (domain == rule_domain or domain.endswith("." + rule_domain)):
                return app_type
        return AppType.UNKNOWN

    def is_ip_blocked(self, source_ip):
        """Check whether a source IP address is blocked."""

        if not source_ip:
            return False
        return source_ip in self.blocked_ips

    def is_app_blocked(self, app_type):
        """Check whether an application type is blocked."""

        if not app_type:
            return False
        return app_type in self.blocked_apps

    def is_domain_blocked(self, domain):
        """Check whether a domain/SNI or its subdomain is blocked."""

        if not domain:
            return False

        domain = domain.lower().strip().rstrip(".")

        for blocked_domain in self.blocked_domains:
            blocked_domain = (blocked_domain.lower().strip().rstrip("."))

            # A rule without a dot ("facebook") is treated as a domain label.
            # This blocks "www.facebook.com" but not "notfacebook.com".
            if "." not in blocked_domain:
                if blocked_domain in domain.split("."):
                    return True
                continue

            if (domain == blocked_domain or domain.endswith("." + blocked_domain)):
                return True
        return False