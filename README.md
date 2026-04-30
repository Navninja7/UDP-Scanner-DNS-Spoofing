# Scapy Class Participation — CS6903 Network Security

- Task 7: UDP Scanner
- Task 11: DNS Spoofing

### Tools & Libraries
- Python 3, Scapy library (https://scapy.net)
- netfilterqueue library for DNS spoofing

### AI / External Assistance
- Took help from Claude AI for code structure and documentation

### Usage: sudo python3 task7.py <target> [-p PORTS] [-t TIMEOUT]

Arguments:
  target              Target IP address to scan

Options:
  -p, --ports         Ports to scan (default: 1-1024)
                        Range:  -p 1-500
                        List:   -p 53,67,123,161
                        Single: -p 53
  -t, --timeout       Seconds to wait per port (default: 2.0)

Examples:
  - sudo python3 task7.py 127.0.0.1                  # scan ports 1-1024 on localhost
  - sudo python3 task7.py 127.0.0.1 -p 1-200         # scan ports 1-200
  - sudo python3 task7.py 127.0.0.53 -p 53           # check if DNS port is open
  - sudo python3 task7.py 8.8.8.8 -p 53,123,161      # scan specific ports on remote host
  - sudo python3 task7.py 127.0.0.1 -p 9999 -t 3    # single port with 3s timeout
  
  
### Usage: sudo python3 task11.py [--spoof DOMAIN=IP ...] [--queue NUM] [--verbose]

Options:
  --spoof             One or more DOMAIN=IP pairs to spoof (default: built-in table)
                        Single:   --spoof example.com=1.2.3.4
                        Multiple: --spoof example.com=1.2.3.4 test.local=10.0.0.1
  --queue             iptables NFQUEUE number to bind to (default: 0)
  --verbose           Print ALL intercepted DNS queries, not just spoofed ones

Examples:
  - sudo python3 task11.py                                         # use built-in spoof table
  - sudo python3 task11.py --verbose                               # show all DNS queries
  - sudo python3 task11.py --spoof example.com=1.2.3.4            # spoof single domain
  - sudo python3 task11.py --spoof a.com=1.2.3.4 b.com=5.6.7.8   # spoof multiple domains
  - sudo python3 task11.py --spoof example.com=1.2.3.4 --verbose  # spoof + show all queries
  - sudo python3 task11.py --queue 1                               # use NFQUEUE number 1

Pre-requisite (run before starting the script):
  sudo iptables -I OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0

Cleanup (run after stopping the script):
  sudo iptables -D OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 0
