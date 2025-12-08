import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import pickle
import os

# --- Configuration ---
# Define the output path for the serialized model
MODEL_DIR = 'models'
MODEL_FILE = os.path.join(MODEL_DIR, 'waf_ml_model.pkl')

# Define the features that match the Pydantic schema in app/main.py
# [user_agent_score, payload_length, request_rate, neuro_independence_score]
FEATURE_COLUMNS = [
    'user_agent_score', 
    'payload_length', 
    'request_rate', 
    'neuro_independence_score'
]

# Define the threat classifications (MUST match the class_labels in ai_detection_module.py)
# 0: 'Normal', 1: 'Intrusion_Attempt', 2: 'Neuro_Risk_Flag', 3: 'DDoS_Attack', ...
TARGET_LABELS = [0, 1, 2, 3]

# --- 1. Data Generation (Mocking) ---

def generate_mock_data(n_samples=1000):
    """Generates a synthetic dataset for WAF threat detection training."""
    print("Generating synthetic WAF threat data...")

    # Normal Traffic (Class 0)
    data_normal = {
        'user_agent_score': np.random.uniform(0.7, 1.0, n_samples), # High score = good user agent
        'payload_length': np.random.randint(20, 100, n_samples),
        'request_rate': np.random.randint(1, 10, n_samples),
        'neuro_independence_score': np.random.uniform(0.7, 1.0, n_samples), # High score = stable
        'label': 0
    }

    # Intrusion Attempt (Class 1) - Low neuro score, suspicious payload length
    data_intrusion = {
        'user_agent_score': np.random.uniform(0.2, 0.6, n_samples // 4),
        'payload_length': np.random.randint(200, 1000, n_samples // 4),
        'request_rate': np.random.randint(1, 5, n_samples // 4),
        'neuro_independence_score': np.random.uniform(0.0, 0.4, n_samples // 4), # Low score = high neuro risk/bot
        'label': 1
    }
    
    # Neuro Risk Flag (Class 2) - Very low neuro score, moderate traffic
    data_neuro_risk = {
        'user_agent_score': np.random.uniform(0.5, 0.8, n_samples // 4),
        'payload_length': np.random.randint(50, 300, n_samples // 4),
        'request_rate': np.random.randint(2, 15, n_samples // 4),
        'neuro_independence_score': np.random.uniform(0.0, 0.2, n_samples // 4), # Critical neuro risk
        'label': 2
    }

    # DDoS Attack (Class 3) - High request rate
    data_ddos = {
        'user_agent_score': np.random.uniform(0.8, 1.0, n_samples // 4),
        'payload_length': np.random.randint(30, 80, n_samples // 4),
        'request_rate': np.random.randint(50, 200, n_samples // 4), # High rate
        'neuro_independence_score': np.random.uniform(0.5, 1.0, n_samples // 4),
        'label': 3
    }

    # Combine dataframes
    df = pd.concat([
        pd.DataFrame(data_normal), 
        pd.DataFrame(data_intrusion), 
        pd.DataFrame(data_neuro_risk),
        pd.DataFrame(data_ddos)
    ], ignore_index=True)

    print(f"Total samples generated: {len(df)}")
    return df

# --- 2. Model Training and Saving ---

def train_and_save_model():
    """Trains a Random Forest model and saves it to a file."""
    
    # Generate data
    data = generate_mock_data()
    
    # Prepare features (X) and target (y)
    X = data[FEATURE_COLUMNS]
    y = data['label']
    
    # Split data (optional for mock, but good practice)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Initialize and train the Random Forest Classifier
    print("Training Random Forest Classifier...")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    print("Training complete.")
    
    # Evaluate (for developer insight)
    y_pred = model.predict(X_test)
    print("\n--- Model Evaluation (Mock Data) ---")
    print(classification_report(y_test, y_pred, zero_division=0, target_names=[
        'Normal', 'Intrusion', 'Neuro_Risk', 'DDoS'
    ]))
    print("------------------------------------\n")
    
    # Create the models directory if it doesn't exist
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Save the trained model using pickle
    with open(MODEL_FILE, 'wb') as file:
        pickle.dump(model, file)
        
    print(f"SUCCESS: Trained model saved to {MODEL_FILE}")

# --- Execute Script ---
if __name__ == "__main__":
    train_and_save_model()
