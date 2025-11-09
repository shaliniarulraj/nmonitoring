from capture.extractor import extract_features
from scapy.layers.inet import IP, TCP

def test_extract_features():
    packet = IP(src="192.168.1.1", dst="8.8.8.8")/TCP()
    features = extract_features(packet)
    assert 'src_ip' in features
