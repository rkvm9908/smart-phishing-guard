import pandas as pd
from joblib import load
from .extract_features import extract_features 

# --- Load Model and Preprocessing Objects ---
try:
    # 1. Load the trained ensemble model (Correct Name)
    model = load("models/ensemble_model.joblib") 
    
    # 2. CRITICAL: Load the scaler used during training
    scaler = load("models/scaler.joblib") 
    
    # 3. Load the label encoder
    label_encoder = load("models/label_encoder.joblib")
    print("Models and Scaler loaded successfully.")

except FileNotFoundError:
    print("Error: Model or preprocessing files not found. Ensure all .joblib files exist in the 'models/' directory.")
    exit()

# --- 3. Get User Input ---
url = input("Enter URL for safety check: ")

# --- 4. Extract Features and Preprocess ---
features_df = extract_features(url) 
features_scaled = scaler.transform(features_df) 

# --- 5. Predict and Display Result ---
pred_array = model.predict(features_scaled)
pred_int = int(pred_array[0])
result_label = label_encoder.inverse_transform([pred_int])[0] 

print("\n--- URL Safety Result ---")
print(f"URL: {url}")

print(f"Prediction: **{result_label.upper()}**")
