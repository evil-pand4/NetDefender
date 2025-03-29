import sys
import argparse
import threading
import signal
import time
import logging
import re
from collections import defaultdict
from math import log2, sqrt

try:
    from scapy.all import (
        sniff,
        ARP,
        DNSQR,
        DNS,
        DNSRR,
        IP
    )
except ImportError:
    print("[!] Scapy not installed. Please install via `pip install scapy`.")
    sys.exit(1)


class ARPMonitor:
    """
    Monitors ARP packets to detect potential spoofing attacks.
    Maintains a mapping from IP -> MAC, raising alerts if there's a conflict.
    """
    def __init__(self, logger):
        self.logger = logger
        self.arp_table = {}

    def process_arp_packet(self, pkt):
        """
        Processes an ARP packet to check for spoofing anomalies.
        If there's a mismatch for an IP address previously seen
        with a different MAC, an alarm is raised.
        """
        if ARP in pkt:
            arp_op = pkt[ARP].op
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc

            # ARP reply or request
            if arp_op == 2 or arp_op == 1:
                if src_ip in self.arp_table:
                    # Check if the MAC is different than what we have on file
                    if self.arp_table[src_ip] != src_mac:
                        self.logger.warning(
                            f"[ALERT] ARP Spoofing suspected! IP {src_ip} was {self.arp_table[src_ip]}, now {src_mac}"
                        )
                else:
                    # New entry discovered
                    self.arp_table[src_ip] = src_mac


class DNSMonitor:
    """
    Monitors DNS packets to detect suspicious domain queries. 
    Uses a basic "domain randomness" check (Shannon entropy) to guess if
    a queried domain might be dynamically generated or suspicious.
    """
    def __init__(self, logger, suspicious_entropy_threshold=3.5):
        """
        suspicious_entropy_threshold: The minimum Shannon entropy considered 'suspicious'.
        """
        self.logger = logger
        self.suspicious_entropy_threshold = suspicious_entropy_threshold
        # Keep counters for repeated suspicious domain queries
        self.suspicious_counts = defaultdict(int)

    @staticmethod
    def shannon_entropy(domain):
        """
        Compute a simplified Shannon entropy for a given domain string.
        A higher value often indicates a randomly generated domain.
        """
        # Remove TLDs or any short domain suffixes we might not want to consider
        domain_stripped = re.sub(r'(\.com|\.net|\.org|\.co|\.io|\.[a-z]{2,3})$', '', domain.lower())
        domain_stripped = domain_stripped.replace('.', '')

        if not domain_stripped:
            return 0.0

        # Count frequency
        freq = {}
        for char in domain_stripped:
            freq[char] = freq.get(char, 0) + 1

        # Shannon entropy
        entropy = 0.0
        for c in freq:
            p = freq[c] / len(domain_stripped)
            entropy -= p * log2(p)

        return entropy

    def process_dns_packet(self, pkt):
        """
        Examines DNS queries for suspicious domains (high entropy).
        """
        if DNS in pkt and DNSQR in pkt and pkt[DNS].opcode == 0:  # Standard query
            query_name = pkt[DNSQR].qname.decode(errors='ignore').rstrip('.')
            if query_name:
                entropy_val = self.shannon_entropy(query_name)
                if entropy_val >= self.suspicious_entropy_threshold:
                    self.suspicious_counts[query_name] += 1
                    self.logger.warning(
                        f"[ALERT] Potentially suspicious domain '{query_name}' (entropy={entropy_val:.2f}). "
                        f"Count={self.suspicious_counts[query_name]}"
                    )


class NetworkMonitor:
    """
    The main class that coordinates ARP and DNS monitoring via Scapy packet sniffing.
    """
    def __init__(self, interface, logger):
        self.interface = interface
        self.logger = logger
        self.arp_monitor = ARPMonitor(logger)
        self.dns_monitor = DNSMonitor(logger)

        # Control flag for sniffing
        self.stop_sniff = threading.Event()
        self.sniff_thread = None

    def start(self):
        """
        Starts sniffing in a background thread.
        """
        self.logger.info(f"Starting packet capture on interface '{self.interface}'...")
        self.sniff_thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self.sniff_thread.start()

    def _sniff_packets(self):
        """
        The main sniff loop that delegates packets to the appropriate monitors.
        """
        sniff(
            iface=self.interface,
            store=False,
            prn=self._process_packet,
            stop_filter=self._should_stop_sniff
        )

    def _process_packet(self, pkt):
        """
        Handles incoming packets, delegating to ARP or DNS monitoring as needed.
        """
        # ARP Check
        if ARP in pkt:
            self.arp_monitor.process_arp_packet(pkt)

        # DNS Check
        if DNS in pkt:
            self.dns_monitor.process_dns_packet(pkt)

    def _should_stop_sniff(self, pkt):
        """
        Called by scapy after each packet is received. If we set the stop_sniff
        event, sniffing stops gracefully.
        """
        return self.stop_sniff.is_set()

    def stop(self):
        """
        Signals the sniff loop to stop and waits for the thread to finish.
        """
        self.logger.info("Stopping packet capture...")
        self.stop_sniff.set()
        if self.sniff_thread:
            self.sniff_thread.join()
        self.logger.info("Packet capture stopped.")


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Advanced Network Monitoring Script using Scapy."
    )
    parser.add_argument(
        "-i", "--interface",
        default="eth0",
        help="Network interface to monitor (default: eth0)"
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path to a log file (default: None; logs to console)."
    )

    args = parser.parse_args()
    interface = args.interface
    log_file = args.output

    # Setup logging
    logger = logging.getLogger("NetworkMonitor")
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    if log_file:
        fh = logging.FileHandler(log_file)
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    else:
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

    # Instantiate Network Monitor
    monitor = NetworkMonitor(interface, logger)

    # Handle CTRL+C nicely
    def signal_handler(sig, frame):
        logger.info("CTRL+C detected. Shutting down...")
        monitor.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    # Start monitoring
    monitor.start()

    # Keep main thread alive until user interrupts
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
