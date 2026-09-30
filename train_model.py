import random
from pathlib import Path
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier

random.seed(42)
rows = []

for _ in range(1200):
    vals = [random.randint(0, 1) for _ in range(5)]
    score = 4*vals[0] + 3*vals[1] + vals[2] + vals[3] + 2*vals[4]
    label = "High Risk" if score >= 6 else ("Medium Risk" if score >= 3 else "Low Risk")
    rows.append(vals + [label])

cols = ["open_network", "weak_security", "hidden_ssid", "low_signal", "suspicious_name", "risk"]
df = pd.DataFrame(rows, columns=cols)

X = df.drop(columns=["risk"])
y = df["risk"]

model = RandomForestClassifier(n_estimators=150, max_depth=6, random_state=42)
model.fit(X, y)

Path("model").mkdir(exist_ok=True)
joblib.dump(model, "model/wifi_risk_model.joblib")
df.to_csv("model/prototype_training_data.csv", index=False)
print("Model trained and saved successfully.")
