from dataclasses import dataclass
from enum import Enum
from typing import Optional

class AppType(Enum):
    UNKNOWN = "UNKNOWN"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    YOUTUBE = "YOUTUBE"
    FACEBOOK = "FACEBOOK"
    GOOGLE = "GOOGLE"
    GITHUB = "GITHUB"
    INSTAGRAM = "INSTAGRAM"
    TWITTER = "TWITTER"
    AMAZON = "AMAZON"
    NETFLIX = "NETFLIX"
    DISCORD = "DISCORD"
    ZOOM = "ZOOM"
    TELEGRAM = "TELEGRAM"
    TIKTOK = "TIKTOK"
    SPOTIFY = "SPOTIFY"
    CLOUDFLARE = "CLOUDFLARE"
    MICROSOFT = "MICROSOFT"
    APPLE = "APPLE"

@dataclass(frozen=True)
class FiveTuple:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str

@dataclass
class Flow:
    five_tuple: FiveTuple
    app_type: AppType = AppType.UNKNOWN
    sni: Optional[str] = None
    blocked: bool = False
    packet_count: int = 0