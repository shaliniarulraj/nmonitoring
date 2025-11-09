"""Verify MongoDB Cloud Connection and Data"""
from pymongo import MongoClient
import os
import sys

MONGODB_URI = os.getenv('MONGODB_URI')
if not MONGODB_URI:
    print("❌ MONGODB_URI not set!")
    print("   Set it with:")
    print("   Windows: setx MONGODB_URI 'your-connection-string'")
    print("   Linux/Mac: export MONGODB_URI='your-connection-string'")
    sys.exit(1)

print("🔌 Connecting to MongoDB...")
try:
    client = MongoClient(MONGODB_URI)
    client.admin.command('ping')
    print("✅ Connected successfully!")
    
    db = client['network_monitor']
    collection = db['packets']
    count = collection.count_documents({})
    
    print(f"\n📊 Database Status:")
    print(f"   Total packets: {count}")
    
    if count > 0:
        latest = collection.find_one(sort=[('timestamp', -1)])
        print(f"\nLatest Packet:")
        print(f"   Source: {latest['src_ip']}")
        print(f"   Destination: {latest['dst_ip']}")
        print(f"   Protocol: {latest['protocol']}")
        print(f"   Size: {latest['packet_size']} bytes")
        
        anomaly_count = collection.count_documents({'packet_size': {'$gt': 4000}})
        print(f"\n🚨 Potential Anomalies:")
        print(f"   Large packets (>4000 bytes): {anomaly_count}")
    else:
        print("\n⚠️  No packets in database yet")
        print("   Run: sudo python sniffer.py --count 50")
        
except Exception as e:
    print(f"❌ Connection failed: {e}")
    sys.exit(1)