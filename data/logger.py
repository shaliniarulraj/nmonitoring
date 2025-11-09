from pymongo import MongoClient
import os
from datetime import datetime

# Cloud MongoDB connection - reads from environment variable
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGODB_URI)
db = client['network_monitor']
collection = db['packets']

def log_packet(packet_data):
    """
    Log packet to MongoDB with timestamp
    Works with both local and cloud MongoDB
    """
    try:
        # Ensure timestamp is datetime object
        if 'timestamp' not in packet_data:
            packet_data['timestamp'] = datetime.now()
        elif isinstance(packet_data['timestamp'], (int, float)):
            packet_data['timestamp'] = datetime.fromtimestamp(packet_data['timestamp'])
        
        # Add email_sent flag for alert tracking
        if 'email_sent' not in packet_data:
            packet_data['email_sent'] = False
        
        collection.insert_one(packet_data)
        return True
    except Exception as e:
        print(f"⚠️  Error logging packet: {e}")
        return False