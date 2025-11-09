from sklearn.preprocessing import StandardScaler, LabelEncoder

def preprocess(df):
    df['protocol'] = LabelEncoder().fit_transform(df['protocol'])
    scaler = StandardScaler()
    scaled = scaler.fit_transform(df[['packet_size', 'protocol']])
    return scaled, scaler
