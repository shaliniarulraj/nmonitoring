from sklearn.ensemble import IsolationForest
import joblib

def train_model(data):
    model = IsolationForest(contamination=0.05)
    model.fit(data)
    joblib.dump(model, 'data/model.pkl')
    return model

def detect_anomaly(model, scaled_data):
    return model.predict(scaled_data)

def classify_anomaly(packet):
    if packet['packet_size'] > 4000:
        return "Oversized Packet"
    elif packet['protocol'] not in ['TCP', 'UDP']:
        return "Unusual Protocol"
    elif packet.get('frequency', 0) > 100:
        return "High Frequency (DDoS)"
    else:
        return "Unknown Anomaly"
