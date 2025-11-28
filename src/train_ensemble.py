import os
import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import glob 
from joblib import dump
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.utils import resample
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from xgboost import XGBClassifier
from extract_features import extract_features

# --- 1. Setup and Load Data (Multi-File Loading Implementation) ---

BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 

# Define correct directories based on project structure (src/model/, src/static/)
# Note: Changing MODEL_DIR to 'model' as per project structure requirement, not 'models'
os.makedirs("models", exist_ok=True)
IMG_DIR = os.path.join(BASE_DIR, 'static', 'img')
DATA_FOLDER = os.path.join(BASE_DIR, 'dataset') 

# Create necessary directories
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(IMG_DIR, exist_ok=True)


# Load dataset: Combine all CSVs from DATA_FOLDER
all_csv_files = glob.glob(os.path.join(DATA_FOLDER, '*.csv'))
df_list = []

if not all_csv_files:
    print("FATAL ERROR: No CSV files found. Exiting.")
    exit()

for file_path in all_csv_files:
    try:
        df_chunk = pd.read_csv(file_path)
        df_list.append(df_chunk)
        print(f"Loaded {os.path.basename(file_path)} with {len(df_chunk)} rows.")
    except Exception as e:
        print(f"ERROR: Could not load {os.path.basename(file_path)}. {e}")

df = pd.concat(df_list, ignore_index=True)
print(f"Total rows in combined dataset: {len(df)}")

df.columns = df.columns.str.lower().str.strip()
df = df.rename(columns={'url': 'URL', 'type': 'label'})

# Map the string labels to their canonical string names (phishing/legit)
df['label'] = df['label'].str.lower().replace({
    'legitimate': 'legit', 
    'safe': 'legit', 
    'phishing': 'phishing',
    'malicious': 'phishing',
    'bad': 'phishing' 
})
# Create the numerical label column based on the string label
df['label'] = df['label'].apply(lambda x: 1 if x == 'phishing' else 0)

# CRITICAL STEP: Extract 7 features for all URLs using your function
print("Extracting 7 features from all URLs...")
extracted_features_list = []
for url in df['URL']:
    features = extract_features(url) 
    extracted_features_list.append(features.iloc[0].to_dict())

# Convert the list of dictionaries back to a DataFrame and combine with the original data
df_features = pd.DataFrame(extracted_features_list)
df = pd.concat([df.reset_index(drop=True), df_features.reset_index(drop=True)], axis=1)

print(f"Feature extraction complete. Total dataset size: {len(df)}")
print(f"Original class distribution:\n{df['label'].value_counts()}")

# --- 2. Balance Classes using Oversampling ---
df['label'] = df['label'].apply(lambda x: 'phishing' if x == 1 else 'legit')

ph_df = df[df["label"] == "phishing"]
lg_df = df[df["label"] == "legit"]

if len(ph_df) < len(lg_df):
    min_df = ph_df
    max_df = lg_df
else:
    min_df = lg_df
    max_df = ph_df

min_up = resample(
    min_df, 
    replace=True, 
    n_samples=len(max_df),
    random_state=42
)

df_balanced = pd.concat([max_df, min_up]).sample(frac=1, random_state=42).reset_index(drop=True)

print("\n--- Balanced Dataset Information ---")
print(f"Final dataset size: {len(df_balanced)}")
print(f"Balanced class distribution:\n{df_balanced['label'].value_counts()}")

# --- 3. Split Data and Feature Selection ---

SELECTED_FEATURE_COLUMNS = [
    "URLLength",
    "NoOfDegitsInURL",
    "NoOfLettersInURL",
    "NoOfQMarkInURL",
    "NoOfEqualsInURL",
    "IsDomainIP",
    "IsHTTPS"
]

X = df_balanced[SELECTED_FEATURE_COLUMNS]
y = df_balanced['label'] 

X_train, X_test, y_train, y_test = train_test_split(
    X, 
    y, 
    test_size=0.2, 
    random_state=42, 
    stratify=y
)
print(f"\nTraining set size: {len(X_train)} samples, using {X_train.shape[1]} features.")
# --- 4. Preprocessing: Encoding and Scaling ---

le = LabelEncoder()
y_train_enc = le.fit_transform(y_train)
y_test_enc = le.transform(y_test)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train) 
X_test_scaled = scaler.transform(X_test)

# --- 5. Train Base Models and 6. Train Ensemble Model ---

print("\n--- Training Ensemble Model (7 Features) ---")

rf = RandomForestClassifier(
    n_estimators=350,
    max_depth=12,
    random_state=42,
    n_jobs=4
)
xgb = XGBClassifier(
    n_estimators=250,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    n_jobs=4,
    random_state=42
)

ensemble = VotingClassifier(
    estimators=[("rf", rf), ("xgb", xgb)],
    voting="soft",
    n_jobs=4
)

ensemble.fit(X_train_scaled, y_train_enc)
print("Ensemble model trained successfully on 7 features.")

print("Performing Cross-Validation...")
scores = cross_val_score(ensemble, X_train_scaled, y_train_enc, cv=5, n_jobs=-1)
print(f"Cross-Validation Scores (5-fold): {scores}")
print(f"Mean CV Accuracy: {scores.mean():.4f}")

# --- 7. Evaluation and Saving ---
preds = ensemble.predict(X_test_scaled)
acc = accuracy_score(y_test_enc, preds)

print("\n--- Final Test Evaluation ---")
print(f"Test Accuracy: {acc:.4f}")

target_names = le.classes_ 
print("\nConfusion Matrix:")
print(confusion_matrix(y_test_enc, preds))
print("\nClassification Report:")
print(classification_report(y_test_enc, preds, target_names=target_names))

# Save model - Corrected Paths (Using MODEL_DIR = 'src/model')
dump(ensemble, "models/ensemble_model.joblib") # Saves the 7-feature model
dump(scaler, "models/scaler.joblib")
dump(le, "models/label_encoder.joblib")
print("\nEnsemble model saved: models/ensemble_model.joblib")

# Save metrics - Corrected Path
metrics = {
    "ensemble_cv_scores": scores.tolist(),
    "ensemble_cv_mean": float(scores.mean()),
    "ensemble_test_accuracy": float(acc)
}
with open(os.path.join(MODEL_DIR, "ensemble_metrics.json"), "w") as f:
    json.dump(metrics, f, indent=4)
print(f"Metrics saved: {MODEL_DIR}/ensemble_metrics.json")

# Accuracy plot - Corrected Path
plt.figure(figsize=(6,4))
plt.bar(["Ensemble Accuracy"], [acc], color='skyblue')
plt.ylim(0.9, 1.0) 
plt.title("Ensemble Model Test Accuracy")
plt.ylabel("Accuracy")
plt.savefig(os.path.join(IMG_DIR, "accuracy.png"), dpi=200, bbox_inches="tight")
plt.close()

print(f"Accuracy plot saved: {IMG_DIR}/accuracy.png")


