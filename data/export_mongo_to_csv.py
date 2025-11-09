import pandas as pd
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('localhost', 27017)
db = client['network_monitor']
collection = db['packets']

# Fetch all documents, excluding MongoDB's _id field
data = list(collection.find({}, {'_id': 0}))

# Convert to DataFrame
df = pd.DataFrame(data)

# Save to CSV
df.to_csv('data/traffic_logs.csv', index=False)
print("Exported to data/traffic_logs.csv")




