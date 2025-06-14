# ml/train_model.py
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Simulate training data (replace with real features if available)
X_train = np.random.rand(1000, 4)  # [packet_count, total_size, byte_rate, pkt_rate]

model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
model.fit(X_train)

joblib.dump(model, "ml/isolation_forest.pkl")
print("✅ Model saved as ml/isolation_forest.pkl")