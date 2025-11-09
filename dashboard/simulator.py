import argparse
from scapy.all import IP, TCP, UDP, Raw, send
import time

def simulate_ddos(target_ip, count, delay):
    print(f"Simulating DDoS to {target_ip} with {count} packets...")
    for _ in range(count):
        packet = IP(dst=target_ip)/TCP(dport=80)
        send(packet, verbose=False)
        time.sleep(delay)

def simulate_large_packet(target_ip, size):
    print(f"Sending oversized packet ({size} bytes) to {target_ip}...")
    payload = "X" * size
    packet = IP(dst=target_ip)/TCP(dport=80)/Raw(load=payload)
    send(packet, verbose=False)

def simulate_weird_protocol(target_ip, port):
    print(f"Sending UDP packet to uncommon port {port} on {target_ip}...")
    packet = IP(dst=target_ip)/UDP(dport=port)
    send(packet, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Anomaly Simulator")
    parser.add_argument("--type", choices=["ddos", "large", "weird"], required=True, help="Type of anomaly")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP address")
    parser.add_argument("--count", type=int, default=100, help="Packet count for DDoS")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between packets (DDoS)")
    parser.add_argument("--size", type=int, default=5000, help="Payload size for large packet")
    parser.add_argument("--port", type=int, default=9999, help="Port for weird protocol")

    args = parser.parse_args()

    if args.type == "ddos":
        simulate_ddos(args.target, args.count, args.delay)
    elif args.type == "large":
        simulate_large_packet(args.target, args.size)
    elif args.type == "weird":
        simulate_weird_protocol(args.target, args.port)

if __name__ == "__main__":
    main()
