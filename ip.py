import ipaddress
import socket
from functools import lru_cache




def is_special_ip(ip: str) -> bool:
    """Allow me to get a better approach in verifying special IPs"""
    try:
        addr = ipaddress.ip_address(ip)

        return (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_unspecified
        )

    except ValueError:
        return True


def get_local_ipv4() -> str:
    """Récupère l'adresse IP locale de la machine hôte."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def get_local_ipv6() -> str:
    """Récupère l'adresse IPv6 locale principale."""
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        # False connection
        s.connect(("2001:4860:4860::8888", 80))
        local_ipv6 = s.getsockname()[0]
        s.close()
        return local_ipv6
    except Exception:
        return ""


@lru_cache(maxsize=1024)
def resolve_ip(ip: str) -> str:
    """
    Traduit une adresse IP en nom de domaine.
    Le cache @lru_cache évite d'interroger le réseau pour des IP déjà vues.
    """
    # Bypass the special IPs
    if is_special_ip(ip):
        return ip

    try:
        nom_hote = socket.gethostbyaddr(ip)[0]

        # Shorten the domain name
        if len(nom_hote) > 30:
            nom_hote = nom_hote[:27] + "..."

        return nom_hote
    except Exception:
        # If the resolving of IP fail
        return ip


LOCAL_IPV4 = get_local_ipv4()
LOCAL_IPV6 = get_local_ipv6()


def is_my_ip(ip_raw: str) -> bool:
    """Vérifie si une adresse (IPv4 ou IPv6) appartient à la machine hôte."""
    if not ip_raw:
        return False
    return bool(ip_raw == LOCAL_IPV4 or (LOCAL_IPV6 and ip_raw == LOCAL_IPV6))
