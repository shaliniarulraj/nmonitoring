from datetime import datetime

def extract_features(packet):
    """
    Extract features from network packet
    Returns dict with packet information
    """
    if packet.haslayer('IP'):
        # Get protocol name from protocol number
        protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        
        proto_num = packet['IP'].proto
        protocol = protocol_map.get(proto_num, f'PROTO-{proto_num}')
        
        # Extract ports if TCP/UDP
        src_port = None
        dst_port = None
        
        if packet.haslayer('TCP'):
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
        elif packet.haslayer('UDP'):
            src_port = packet['UDP'].sport
            dst_port = packet['UDP'].dport
        
        return {
            'src_ip': packet['IP'].src,
            'dst_ip': packet['IP'].dst,
            'protocol': protocol,
            'packet_size': len(packet),
            'timestamp': datetime.fromtimestamp(float(packet.time)),
            'src_port': src_port,
            'dst_port': dst_port,
            'ttl': packet['IP'].ttl
        }
    return {}