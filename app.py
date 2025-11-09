from flask import Flask, render_template, jsonify, request, redirect, url_for
from pymongo import MongoClient
import pandas as pd
from analysis.preprocess import preprocess
from analysis.anomaly_detector import detect_anomaly
import joblib
import subprocess
from alerts.email_alerts import send_email
from collections import defaultdict
from flask_cors import CORS
from pymongo import MongoClient
import os
app = Flask(__name__)
CORS(app)


# Cloud MongoDB connection
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGODB_URI)
collection = client['network_monitor']['packets']



model = joblib.load('data/model.pkl')

# 🔹 Classify anomaly type
def classify_anomaly(packet):
    if packet['packet_size'] > 4000:
        return "Oversized Packet"
    elif packet['protocol'] not in ['TCP', 'UDP']:
        return "Unusual Protocol"
    elif packet.get('frequency', 0) > 100:
        return "High Frequency (DDoS)"
    else:
        return "Unknown Anomaly"

# 🔹 Bulk alert sender with grouping, severity, timestamp range, and dashboard link
def send_bulk_alert(anomalies):
    if not anomalies:
        return

    grouped = defaultdict(list)
    timestamps = []

    for row in anomalies:
        anomaly_type = classify_anomaly(row)
        grouped[anomaly_type].append(row)
        timestamps.append(row['timestamp'])

    start_time = min(timestamps).strftime("%Y-%m-%d %H:%M:%S")
    end_time = max(timestamps).strftime("%Y-%m-%d %H:%M:%S")

    severity_map = {
        "Oversized Packet": "🔴 High",
        "Unusual Protocol": "🟠 Medium",
        "High Frequency (DDoS)": "🔴 High",
        "Unknown Anomaly": "🟡 Low"
    }

    dashboard_url = "http://127.0.0.1:5000"

    summary_lines = [
        f"📊 Anomaly Report ({len(anomalies)} total)",
        f"🕒 Time Range: {start_time} → {end_time}",
        f"🔗 View live dashboard: {dashboard_url}",
        "\n📌 Type Breakdown:"
    ]
    for anomaly_type, rows in grouped.items():
        severity = severity_map.get(anomaly_type, "🟡 Low")
        summary_lines.append(f"- {anomaly_type}: {len(rows)} ({severity})")

    summary = "\n".join(summary_lines)

    body = summary + "\n\n📋 Detailed Anomalies:\n"
    for anomaly_type, rows in grouped.items():
        severity = severity_map.get(anomaly_type, "🟡 Low")
        body += f"\n{severity} {anomaly_type} ({len(rows)}):\n"
        for row in rows:
            body += f"""  - Src: {row.get('src_ip', 'N/A')}, Dst: {row.get('dst_ip', 'N/A')}, Proto: {row.get('protocol', 'N/A')}, Size: {row['packet_size']} bytes, Time: {row['timestamp']}\n"""

    subject = f"Anomaly Report: {len(anomalies)} events detected"

    try:
        send_email(subject, body)
        for row in anomalies:
            collection.update_one({"_id": row["_id"]}, {
                "$set": {
                    "email_sent": True,
                    "anomaly_type": classify_anomaly(row)
                }
            })
        print(f"📧 Bulk email sent for {len(anomalies)} anomalies.")
    except Exception as e:
        print(f"❌ Failed to send bulk email: {e}")

@app.route('/simulate', methods=['POST'])
def simulate():
    anomaly_type = request.form['type']
    cmd = ["python", "dashboard/simulator.py", "--type", anomaly_type]
    subprocess.Popen(cmd)
    return redirect(url_for('dashboard'))

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/traffic')
def traffic_data():
    packets = list(collection.find().sort('timestamp', -1).limit(100))
    df = pd.DataFrame(packets)

    if df.empty:
        return jsonify({"labels": [], "values": [], "anomalies": [], "anomalyTypes": []})

    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values('timestamp')

    scaled, _ = preprocess(df)
    preds = detect_anomaly(model, scaled)
    df['anomaly'] = preds

    labels = df['timestamp'].dt.strftime('%H:%M:%S').tolist()
    values = df['packet_size'].tolist()
    anomalies = df['anomaly'].tolist()

    anomaly_types = []
    unsent_anomalies = []

    for i, row in df.iterrows():
        if row['anomaly'] == -1:
            anomaly_types.append(classify_anomaly(row))
            if not row.get('email_sent', False):
                unsent_anomalies.append(row)
        else:
            anomaly_types.append("")

    send_bulk_alert(unsent_anomalies)

    return jsonify({
        "labels": labels,
        "values": values,
        "anomalies": anomalies,
        "anomalyTypes": anomaly_types
    })

@app.route('/api/email-log')
def email_log():
    alerts = list(collection.find(
        {"anomaly": -1, "email_sent": True}
    ).sort("timestamp", -1).limit(20))

    for alert in alerts:
        alert["_id"] = str(alert["_id"])
        alert["timestamp"] = alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
        alert["anomaly_type"] = classify_anomaly(alert)

    return jsonify(alerts)
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
