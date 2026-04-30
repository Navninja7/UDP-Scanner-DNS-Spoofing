#!/usr/bin/env python3
"""
Task 7: UDP Scanner

Objective: Scan UDP ports by sending UDP packets and detecting ICMP Port Unreachable responses.
Extension: Handles timeout cases and classifies ports as open/filtered.

NOTE: Run with root/sudo privileges. Perform only in controlled environments.
"""

from scapy.all import IP, UDP, ICMP, sr1, conf
import argparse
import sys

# Suppress Scapy runtime output
conf.verb = 0


def scan_udp_port(target_ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Send a UDP packet to the target port and classify the response.

    Port states:
      - open/filtered : No response (UDP service may be running, or packet was dropped by firewall)
      - closed        : ICMP Type 3, Code 3 (Port Unreachable) received
      - filtered      : Other ICMP Type 3 codes (e.g., host/network unreachable)

    Args:
        target_ip : Destination IP address
        port      : UDP port number to probe
        timeout   : Time (seconds) to wait for a response

    Returns:
        String state: "open|filtered", "closed", or "filtered"
    """
    # Craft IP/UDP packet with empty payload
    packet = IP(dst=target_ip) / UDP(dport=port)

    response = sr1(packet, timeout=timeout, verbose=0)

    if response is None:
        # No reply -> port is open or silently filtered
        return "open|filtered"

    if response.haslayer(ICMP):
        icmp_type = response[ICMP].type
        icmp_code = response[ICMP].code

        if icmp_type == 3 and icmp_code == 3:
            # ICMP Port Unreachable -> port is definitively closed
            return "closed"
        elif icmp_type == 3:
            # Other ICMP unreachable codes -> administratively filtered
            return "filtered"

    # Got a UDP response -> port is open
    return "open"


def run_scan(target_ip: str, ports: list, timeout: float = 2.0) -> None:
    """
    Scan a list of UDP ports and print results.

    Args:
        target_ip : Target host IP
        ports     : List of port numbers to scan
        timeout   : Per-port response timeout in seconds
    """
    print(f"\n{'='*55}")
    print(f"  UDP Port Scan | Target: {target_ip}")
    print(f"  Ports: {ports[0]}–{ports[-1]}  |  Timeout: {timeout}s")
    print(f"{'='*55}")
    print(f"{'PORT':<10} {'STATE':<20} {'NOTE'}")
    print(f"{'-'*55}")

    results = {"open|filtered": [], "open": [], "closed": [], "filtered": []}

    for port in ports:
        state = scan_udp_port(target_ip, port, timeout)
        results[state].append(port)

        # Only print non-closed ports to keep output clean
        if state != "closed":
            note = {
                "open|filtered": "No response; may be open or firewall-dropped",
                "open":          "UDP response received",
                "filtered":      "ICMP unreachable (not port-unreachable)",
            }.get(state, "")
            print(f"{port:<10} {state:<20} {note}")

    # Summary
    print(f"\n{'='*55}")
    print("  SCAN SUMMARY")
    print(f"{'='*55}")
    total = len(ports)
    for state, port_list in results.items():
        if port_list:
            print(f"  {state:<20}: {len(port_list)}/{total} ports  -> {port_list[:10]}"
                  f"{'...' if len(port_list) > 10 else ''}")
    print(f"{'='*55}\n")


def parse_ports(port_arg: str) -> list:
    """
    Parse port argument. Supports:
      - Single port: "80"
      - Range: "1-1024"
      - Comma list: "22,53,80,443"

    Returns sorted list of integers.
    """
    ports = set()
    for part in port_arg.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="Task 7: UDP Port Scanner (Scapy)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Examples:\n"
               "  sudo python3 task7.py 192.168.1.1\n"
               "  sudo python3 task7.py 192.168.1.1 -p 1-500\n"
               "  sudo python3 task7.py 192.168.1.1 -p 53,67,68,69,123 -t 3\n"
    )
    parser.add_argument("target", help="Target IP address")
    parser.add_argument(
        "-p", "--ports", default="1-1024",
        help="Ports to scan. Range (1-1024), list (22,80,443), or single (53). Default: 1-1024"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=2.0,
        help="Timeout per port in seconds (default: 2.0)"
    )

    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"[ERROR] Invalid port specification: {e}")
        sys.exit(1)

    print(f"[*] Starting UDP scan on {args.target} ...")
    print("[!] Note: UDP scanning requires root privileges and may be slow.")

    run_scan(args.target, ports, args.timeout)


if __name__ == "__main__":
    main()
