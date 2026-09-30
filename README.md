# WiFiShield AI — IDT Review 2 MVP

### Setup in PyCharm
1. Open this folder in PyCharm.
2. Create/select a Python interpreter or virtual environment.
3. Open the PyCharm Terminal.
4. Run: `pip install -r requirements.txt`
5. Run: `python train_model.py`
6. Run: `python app.py`
7. Open `http://127.0.0.1:5000`

### Demo
Click **Run Demo Network** first for a guaranteed presentation output.
Then click **Scan Nearby Wi-Fi** on Windows with Wi-Fi enabled.

### What to say
"WiFiShield AI collects available Wi-Fi security indicators, converts them into model features, uses a Random Forest classifier for prototype risk classification, and presents an understandable risk level with reasons and recommendations."

### Important limitation
The included training data is synthetic for prototype demonstration. It must be replaced with a properly sourced and labelled dataset for a final research-grade system. The risk result is indicative, not a guarantee of safety.
