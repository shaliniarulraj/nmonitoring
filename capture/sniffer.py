"""
Network Sniffer - Production Version
Captures packets continuously and stores in cloud MongoDB
"""

from scapy.all import sniff
from capture.extractor import extract_features
from data.logger import log_packet
import signal
import sys

# Statistics
packet_count = 0
success_count = 0
error_count = 0

def handle_packet(packet):
    """Process each captured packet"""
    global packet_count, success_count, error_count
    
    try:
        features = extract_features(packet)
        if isinstance(features, dict) and features:
            if log_packet(features):
                packet_count += 1
                success_count += 1
                
                # Show progress every 10 packets
                if packet_count % 10 == 0:
                    print(f"📦 Captured: {packet_count} packets | ✅ Success: {success_count} | ❌ Errors: {error_count}", end='\r')
            else:
                error_count += 1
    except Exception as e:
        error_count += 1
        if error_count % 10 == 0:
            print(f"\n⚠️  Error processing packet: {e}")

def signal_handler(sig, frame):
    """Graceful shutdown on Ctrl+C"""
    print(f"\n\n{'='*60}")
    print(f"🛑 Stopping packet capture...")
    print(f"📊 Final Statistics:")
    print(f"   Total packets processed: {packet_count}")
    print(f"   Successfully logged: {success_count}")
    print(f"   Errors: {error_count}")
    print(f"   Success rate: {(success_count/packet_count*100):.1f}%" if packet_count > 0 else "   Success rate: N/A")
    print(f"{'='*60}")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def start_sniffing(interface=None, count=0):
    """
    Start capturing network packets
    
    Args:
        interface: Network interface (None = default/all)
        count: Number of packets to capture (0 = infinite)
    """
    print("=" * 60)
    print("  🛡️  Network Traffic Monitor - Packet Capture")
    print("=" * 60)
    print(f"📡 Interface: {interface or 'default (all interfaces)'}")
    print(f"📊 Mode: {'Continuous capture' if count == 0 else f'Capturing {count} packets'}")
    print(f"💾 Storing to: Cloud MongoDB")
    print(f"⚠️  Press Ctrl+C to stop gracefully")
    print("=" * 60)
    print()
    
    try:
        sniff(
            prn=handle_packet,
            store=False,
            count=count,
            iface=interface
        )
    except PermissionError:
        print("\n" + "=" * 60)
        print("❌ PERMISSION ERROR!")
        print("=" * 60)
        print("Packet capture requires administrator/root privileges.")
        print()
        print("Solutions:")
        print("  • Windows: Run Command Prompt as Administrator")
        print("  • Linux/Mac: Use 'sudo python sniffer.py'")
        print("=" * 60)
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Traffic Monitor - Packet Sniffer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Capture 50 packets for testing:
    python sniffer.py --count 50
    
  Capture continuously:
    sudo python sniffer.py
    
  Capture from specific interface:
    sudo python sniffer.py --interface eth0
    sudo python sniffer.py --interface "Wi-Fi"  (Windows)
        """
    )
    
    parser.add_argument(
        '--interface', '-i',
        help='Network interface (e.g., eth0, wlan0, "Wi-Fi")',
        default=None
    )
    
    parser.add_argument(
        '--count', '-c',
        type=int,
        default=0,
        help='Number of packets to capture (0 = infinite)'
    )
    
    args = parser.parse_args()
    
    start_sniffing(
        interface=args.interface,
        count=args.count
    )