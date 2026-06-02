# 🔐 Phishing URL Detection Using Ensemble Learning

![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Ensemble%20Learning-orange)
![Scikit-Learn](https://img.shields.io/badge/Scikit--Learn-ML-F7931E?logo=scikitlearn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-Data%20Analysis-150458?logo=pandas&logoColor=white)
![NumPy](https://img.shields.io/badge/NumPy-Numerical%20Computing-013243?logo=numpy&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-000000?logo=flask&logoColor=white)
![Status](https://img.shields.io/badge/Project-Completed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

## 📖 Overview

Phishing attacks are among the most common cybersecurity threats, where attackers create malicious websites that mimic legitimate platforms to steal sensitive information such as usernames, passwords, and banking credentials.

This project presents a **Phishing URL Detection System using Ensemble Learning**, capable of identifying whether a URL is legitimate or phishing based on extracted URL features. Multiple machine learning algorithms are combined using ensemble techniques to improve prediction accuracy and reliability.

The system analyzes URL characteristics, performs feature extraction, and classifies URLs as **Legitimate** or **Phishing** using trained machine learning models.

---

## ✨ Features

- URL-Based Phishing Detection
- Feature Extraction from URLs
- Ensemble Learning Approach
- Real-Time URL Prediction
- Machine Learning-Based Classification
- User-Friendly Web Interface
- Fast and Accurate Detection
- Secure Prediction Process
- Model Training and Evaluation
- Scalable Architecture

---

## 🛠️ Tech Stack

### Programming Language
- Python

### Machine Learning
- Scikit-Learn
- Ensemble Learning Models
- Random Forest
- Decision Tree
- Gradient Boosting
- Voting Classifier

### Data Processing
- Pandas
- NumPy

### Web Framework
- Flask

### Frontend
- HTML5
- CSS3
- JavaScript
- Bootstrap

---

## 📂 Project Structure

```bash
smart-phishing-guard/
│
├── dataset/
│   ├── phishing_urls.csv
│
├── model/
│   ├── trained_model.pkl
│   ├── scaler.pkl
│
├── src/
│   ├── data_preprocessing.py
│   ├── feature_extraction.py
│   ├── model_training.py
│   ├── prediction.py
│
├── templates/
│   ├── index.html
│   └── result.html
│
├── static/
│   ├── css/
│   ├── js/
│   └── images/
│
├── app.py
├── requirements.txt
├── README.md
└── dataset.csv
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/your-username/smart-phishing-guard.git
```

### Navigate to Project Folder

```bash
cd smart-phishing-guard
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Virtual Environment

#### Windows

```bash
venv\Scripts\activate
```

#### Linux / Mac

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

### Open Browser

```bash
http://127.0.0.1:5000
```

---

## 🔄 Workflow

### 1️⃣ Dataset Collection

- Collect phishing and legitimate URLs.
- Store and organize data for training.

### 2️⃣ Data Preprocessing

- Clean dataset.
- Remove duplicates and missing values.
- Prepare data for feature extraction.

### 3️⃣ Feature Extraction

Extract URL-based features such as:

- URL Length
- Domain Length
- Presence of HTTPS
- Number of Dots
- Special Characters
- Suspicious Keywords
- Subdomain Count
- IP Address Usage

### 4️⃣ Model Training

Train multiple machine learning models:

- Decision Tree
- Random Forest
- Gradient Boosting

Combine models using Ensemble Learning.

### 5️⃣ Prediction

- User enters URL.
- Features are extracted.
- Ensemble model predicts:
  - Legitimate URL ✅
  - Phishing URL ⚠️

---

## 📊 System Architecture

```text
URL Input
    │
    ▼
Feature Extraction
    │
    ▼
Data Preprocessing
    │
    ▼
Ensemble Learning Model
    │
    ▼
Prediction Engine
    │
    ▼
Result Display
```

---

## 📈 Model Performance

The ensemble learning approach improves detection performance by combining predictions from multiple classifiers.

### Evaluation Metrics

- Accuracy
- Precision
- Recall
- F1 Score
- Confusion Matrix

### Benefits of Ensemble Learning

- Higher Accuracy
- Reduced Overfitting
- Better Generalization
- Improved Prediction Reliability

---

## 🎯 Key Benefits

- Detects phishing websites effectively.
- Improves cybersecurity awareness.
- Reduces risk of credential theft.
- Fast prediction and analysis.
- Scalable for real-world deployment.
- Easy-to-use web interface.

---

## 🔒 Security Impact

- Helps identify malicious URLs before access.
- Supports safer web browsing.
- Protects users from phishing attacks.
- Enhances online security awareness.

## 📈 Future Enhancements

- Deep Learning-Based Detection
- Real-Time Browser Extension
- API Integration
- Domain Reputation Analysis
- WHOIS Information Analysis
- Live Threat Intelligence Integration
- Cloud Deployment

---

## 🎓 Learning Outcomes

- Machine Learning Model Development
- Ensemble Learning Techniques
- Feature Engineering
- Data Preprocessing
- Flask Web Development
- Model Deployment
- Cybersecurity Applications of AI

---

## Author

**Mathuprasanth R K**
M.Sc Information Technology

---

## ⭐ Support

If you found this project useful, consider giving it a **Star ⭐** on GitHub.

---

## 📌 Project Goal

To develop an intelligent phishing URL detection system using ensemble machine learning techniques that accurately identifies malicious websites, enhances cybersecurity awareness, and helps protect users from online phishing attacks.
