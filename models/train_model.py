import pandas as pd
from analysis.preprocess import preprocess
from analysis.anomaly_detector import train_model

df = pd.read_csv('data/traffic_logs.csv')
scaled, _ = preprocess(df)
train_model(scaled)
