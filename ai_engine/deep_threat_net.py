import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.optimizers import Adam

class EnterpriseDeepThreatEngine:
    def __init__(self):
        print("[*] Initializing Enterprise TensorFlow Deep Threat Engine (v2.0)...")
        try:
            # Build Deep Neural Network Architecture using explicit Input layer
            self.model = Sequential([
                Input(shape=(5,)),
                Dense(32, activation='relu'),
                Dropout(0.2),
                Dense(16, activation='relu'),
                Dense(8, activation='relu'),
                Dense(1, activation='sigmoid')
            ])
            
            self.model.compile(
                optimizer=Adam(learning_rate=0.001),
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Robust pre-training dataset simulating enterprise security logs
            X_train = np.array([
                [0.1, 0.05, 0.0, 0.1, 0.2],
                [0.8, 0.90, 1.0, 0.9, 0.9],
                [0.2, 0.10, 0.0, 0.2, 0.3],
                [0.9, 0.95, 1.0, 0.8, 0.95],
                [0.15, 0.02, 0.0, 0.05, 0.1]
            ], dtype=np.float32)
            
            y_train = np.array([0, 1, 0, 1, 0], dtype=np.float32)
            
            self.model.fit(X_train, y_train, epochs=5, batch_size=2, verbose=0)
            print("[+] TensorFlow Deep Neural Network successfully trained & loaded in-memory.")
            
        except Exception as e:
            print(f"[-] Error initializing TensorFlow Deep Engine: {str(e)}")
            self.model = None

    def predict_deep_threat(self, risk_score, anomaly_score, misp_match, time_dev, payload_size):
        if self.model is None:
            return {"tensorflow_deep_score": 0.0, "is_advanced_threat": False}
            
        try:
            features = np.array([[
                float(risk_score) / 100.0,
                float(anomaly_score) / 10.0,
                1.0 if misp_match else 0.0,
                float(time_dev),
                float(payload_size) / 1000.0
            ]], dtype=np.float32)
            
            prediction = float(self.model.predict(features, verbose=0)[0][0])
            is_advanced_threat = bool(prediction > 0.65)
            
            return {
                "tensorflow_deep_score": round(prediction * 100, 2),
                "is_advanced_threat": is_advanced_threat
            }
        except Exception as e:
            print(f"[-] TensorFlow prediction error: {str(e)}")
            return {"tensorflow_deep_score": 0.0, "is_advanced_threat": False}
