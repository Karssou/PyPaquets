import argparse
import time
from collections import Counter, deque

import keyboard
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet6 import IPv6
from scapy.sendrecv import AsyncSniffer
from scapy.layers.tls.handshake import TLSClientHello

from ip import is_my_ip, resolve_ip


def validate_port(value):
    """Verify that the port is in between 1 and 65535."""
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not an integer")

    if not (1 <= port <= 65535):
        raise argparse.ArgumentTypeError(
            f"The port {port} is invalid. It needs to be between 1 and 65535."
        )

    return port


def analyse_arguments():
    """Check the command line arguments for the main program"""
    parser = argparse.ArgumentParser(description="Network Analyser CLI - Project CS50x")
    parser.add_argument(
        "-p", "--protocol", choices=["tcp", "udp", "icmp"], help="Filter by protocol"
    )
    parser.add_argument(
        "--port",
        type=validate_port,
        help="Filter by source or destination port (ex: 443, 80)",
    )
    parser.add_argument(
        "--ip", type=str, help="Filter by IP address (source or destination)"
    )
    return parser.parse_args()


def build_filter_bpf(args):
    """Translate user arguments into BPF filter for Scapy."""
    conditions = []
    if args.protocol:
        conditions.append(args.protocol.lower())
    if args.port:
        conditions.append(f"port {args.port}")
    if args.ip:
        conditions.append(f"host {args.ip}")

    # Assemble the condition for the bfp
    bpf_filter = " and ".join(conditions) if conditions else None
    return bpf_filter


stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "dns": 0, "autres": 0}
derniers_paquets = deque(maxlen=15)
ip_counter = Counter()


def get_dns_query(packet):
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]

    if not dns.qr:  # 0 = query
        if dns.qd and isinstance(dns.qd, DNSQR):
            return dns.qd.qname.decode(errors="ignore").rstrip(".")

    return None


def get_tls_sni(packet) -> str | None:

    if packet.haslayer(TLSClientHello):
        try:
            client_hello = packet[TLSClientHello]
            if hasattr(client_hello, "extensions") and client_hello.extensions:
                for ext in client_hello.extensions:
                    if hasattr(ext, "server_names") and ext.server_names:
                        for server_name in ext.server_names:
                            # Décodage du nom de domaine
                            return server_name.data.decode("utf-8", errors="ignore")
        except Exception:
            return None
    return None


def analyse_paquet(paquet):
    """Analyse a paquet to retrieve its IP address & resolve it"""
    stats["total"] += 1

    domain = get_tls_sni(paquet)

    if domain:
        protocole = "HTTPS"
        couleur = "bright_green"
        stats["tcp"] += 1

    protocole = "OTHER"
    couleur = "white"

    if paquet.haslayer(TCP):
        protocole = "TCP"
        couleur = "green"
        stats["tcp"] += 1
    elif paquet.haslayer(DNS):
        query_name = get_dns_query(paquet)
        if query_name:
            protocole = (
                f"DNS ({query_name[:15]}...)"
                if len(query_name) > 18
                else f"DNS ({query_name})"
            )
        else:
            protocole = "DNS"
        couleur = "bright_yellow"  # Rich utilise 'bright_yellow' ou une couleur hexa
        stats["dns"] += 1
    elif paquet.haslayer(UDP):
        protocole = "UDP"
        couleur = "cyan"
        stats["udp"] += 1

    elif paquet.haslayer(ICMP):
        protocole = "ICMP"
        couleur = "yellow"
        stats["icmp"] += 1
    else:
        stats["autres"] += 1

    raw_src, raw_dst = "", ""

    if paquet.haslayer(IP):
        raw_src = paquet[IP].src
        raw_dst = paquet[IP].dst
    elif paquet.haslayer(IPv6):
        raw_src = paquet[IPv6].src
        raw_dst = paquet[IPv6].dst

    if raw_src or raw_dst:
        # Resolve Domain name
        ip_src = resolve_ip(raw_src)
        ip_dst = resolve_ip(raw_dst)

        key_src = "You" if is_my_ip(raw_src) else ip_src
        key_dst = "You" if is_my_ip(raw_dst) else ip_dst

        if raw_src:
            ip_counter[key_src] += 1
        if raw_dst:
            ip_counter[key_dst] += 1

        if is_my_ip(raw_src):
            ip_src = f"[bold cyan]YOU[/bold cyan] ({ip_src})"
        if is_my_ip(raw_dst):
            ip_dst = f"[bold cyan]YOU[/bold cyan] ({ip_dst})"
    else:
        ip_src, ip_dst = "Non-IP", "Non-IP"

    taille = len(paquet)

    derniers_paquets.append(
        (f"[{couleur}]{protocole}[/{couleur}]", ip_src, ip_dst, f"{taille} octets")
    )


def generateCLI(en_pause=False, filtre_actif="Aucun") -> Layout:
    """Generate the function interface thanks to the RICH library"""

    layout = Layout()

    layout.split_column(Layout(name="header", size=6), Layout(name="body"))

    layout["body"].split_row(
        Layout(name="journal", ratio=7), Layout(name="top_ips", ratio=3)
    )

    # Header
    titre_status = (
        "[bold red] [PAUSE] [/bold red]"
        if en_pause
        else "[bold green] [LIVE] [/bold green]"
    )
    titre_panel = f"PyPacket - Statistics {titre_status} | Active filter : [yellow]{filtre_actif}[/yellow]"

    texte_stats = (
        f"[bold]Total recorded:[/bold] {stats['total']} paquets\n"
        f"[green]TCP:[/green] {stats['tcp']} | "
        f"[cyan]UDP:[/cyan] {stats['udp']} | "
        f"[yellow]ICMP:[/yellow] {stats['icmp']} | "
        f"Others: {stats['autres']}\n"
        f"[dim]Astuce : Press SPACE to toggle pause/resume[/dim]"
    )
    layout["header"].update(Panel(texte_stats, title=titre_panel))

    # Traffic logs
    tableau_journal = Table(expand=True, title="Traffic logs(15 derniers paquets)")
    tableau_journal.add_column("Protocol", justify="center", style="bold")
    tableau_journal.add_column("Source IP", justify="center")
    tableau_journal.add_column("Destination IP", justify="center")
    tableau_journal.add_column("Size", justify="right")

    for pkt in reversed(derniers_paquets):
        tableau_journal.add_row(pkt[0], pkt[1], pkt[2], pkt[3])

    layout["journal"].update(
        Panel(tableau_journal, border_style="red" if en_pause else "blue")
    )

    # Top 5 of IP address
    tableau_top = Table(expand=True, title="Top 5 - IP Address")
    tableau_top.add_column("Adress / Host", justify="left", style="yellow")
    tableau_top.add_column("Paquets", justify="right", style="bold magenta")

    for ip, count in ip_counter.most_common(5):
        tableau_top.add_row(str(ip), str(count))

    layout["top_ips"].update(Panel(tableau_top, border_style="yellow"))

    return layout


if __name__ == "__main__":
    args = analyse_arguments()
    bpf_filtre = build_filter_bpf(args)

    console = Console()
    console.clear()

    sniffer = AsyncSniffer(prn=analyse_paquet, filter=bpf_filtre, store=False)
    sniffer.start()

    en_pause = False
    description_filtre = bpf_filtre if bpf_filtre else "None (Capture All)"

    try:
        with Live(
            generateCLI(
                en_pause,
                description_filtre,
            ),
            refresh_per_second=10,
            screen=True,
        ) as live:
            while True:
                if keyboard.is_pressed("space"):
                    en_pause = not en_pause
                    live.update(generateCLI(en_pause, description_filtre))
                    time.sleep(0.3)

                if not en_pause:
                    live.update(generateCLI(en_pause, description_filtre))

                time.sleep(0.1)

    except KeyboardInterrupt:
        if sniffer.running:
            sniffer.stop()
        console.print("\n[bold red]Recording stopped by the user[/bold red]")
        console.print(
            f"Final bilan : {stats['total']} paquets analysed with the filter : {description_filtre}"
        )
