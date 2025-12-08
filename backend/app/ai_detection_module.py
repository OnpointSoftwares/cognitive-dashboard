import pickle
import os
import time
import venv
from collections import defaultdict, deque
import numpy as np

# --- Ai Detection Module Configuration ---

# Define the directory where the ML model is stored
MODEL_FILEPATH = os.path.join(os.getcwd(), 'models', 'waf_ml_model.pkl')

# Define the classification labels (MUST match the training script output)
CLASS_LABELS = {
    0: 'Normal',
    1: 'Intrusion_Attempt',
    2: 'Neuro_Risk_Flag',
    3: 'DDoS_Attack'
    # Add other categories here as the model becomes more complex
}

# --- Core Detection Module ---

class MLDetectionModule:
    """
    Manages the loading, prediction, and state (rate limiting) for the WAF ML model.
    """
    
    def __init__(self):
        self.model = None
        self.is_model_loaded = False
        self.error_message = "Unknown Error"
        
        # State: Store last 10 request times for each IP for rate tracking
        self.request_timestamps = defaultdict(lambda: deque(maxlen=10)) 
        
        # Attempt to load the model immediately on initialization
        self._load_model()
        print(f"MLDetectionModule initialized. Model loaded: {self.is_model_loaded}")
        
    def _load_model(self):
        """Loads the pre-trained model from disk."""
        try:
            print(f"Attempting to load model from: {MODEL_FILEPATH}")
            with open(MODEL_FILEPATH, 'rb') as f:
                self.model = pickle.load(f)
            self.is_model_loaded = True
            self.error_message = None
        except FileNotFoundError:
            self.is_model_loaded = False
            self.error_message = "Model file not found. Prediction will fail until model is trained and saved."
            print("WARNING: Model file not found. Prediction will fail until model is trained and saved.")
        except Exception as e:
            self.is_model_loaded = False
            self.error_message = f"Model loading failed: {e}"
            print(f"ERROR: Failed to load model: {e}")
            
    def update_rate_tracker(self, ip_address: str) -> float:
        """
        Updates the request timestamp for the given IP and calculates the current 
        request rate (requests per second).
        
        This logic simulates the feature required for DDoS detection.
        """
        current_time = time.time()
        
        # Add the current time to the deque for the IP
        self.request_timestamps[ip_address].append(current_time)
        
        timestamps = self.request_timestamps[ip_address]
        
        # We need at least 2 timestamps to calculate a rate
        if len(timestamps) < 2:
            return 1.0 # Assume a low rate for the first few requests

        # Calculate the time window between the oldest and newest request
        time_window = timestamps[-1] - timestamps[0]
        
        # If the time window is very small (less than 1 second), prevent division by zero
        # and assume a high rate.
        if time_window < 0.01:
            time_window = 0.01 
            
        # Rate = (Number of requests - 1) / Time window
        # Rate is calculated over the full window of requests stored in the deque.
        request_count = len(timestamps)
        
        request_rate = (request_count - 1) / time_window
        
        # Return a normalized or raw rate value for the ML model
        # We return the raw rate, which is the feature used by the training script
        return request_rate

    def predict(self, features: np.ndarray) -> dict:
        """
        Performs threat prediction using the loaded ML model.
        :param features: A numpy array of WAF features.
        :return: A dictionary containing classification and confidence.
        """
        if not self.is_model_loaded or self.model is None:
            raise RuntimeError(f"ML Model is not loaded. Status: {self.error_message}")
            
        # Predict the class index (e.g., 0, 1, 2, 3)
        prediction_index = self.model.predict(features)[0]
        
        # Predict the probabilities for all classes
        probabilities = self.model.predict_proba(features)[0]
        
        # Get the confidence of the predicted class
        confidence = probabilities[prediction_index]
        
        # Map the index to the human-readable label
        classification_label = CLASS_LABELS.get(prediction_index, "Unknown")
        
        return {
            "classification": classification_label,
            "confidence": float(confidence)
        }

# --- High-level AI Detector Wrapper ---
class AIDetector:
    """
    High-level interface for AI-based threat detection.
    Wraps MLDetectionModule for easy integration.
    """
    def __init__(self):
        self.detector = MLDetectionModule()

    def analyze_flow(self, feature_vector: np.ndarray) -> dict:
        """
        Analyze a network flow's features and return the prediction.
        :param feature_vector: Numpy array of features (shape: 1, N)
        :return: dict with 'classification' and 'confidence'
        """
        return self.detector.predict(feature_vector)
