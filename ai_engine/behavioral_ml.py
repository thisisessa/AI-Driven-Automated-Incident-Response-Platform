import numpy as np
from sklearn.ensemble import IsolationForest

class BehavioralAnomalyDetector:
    def __init__(self):
        # Unsupervised ML Model for Behavioral Anomaly / Insider Threat Detection
        self.model = IsolationForest(contamination=0.15, random_state=42)
        
        # Training baseline matrix: [activity_volume, off_hours_flag]
        X_train = np.array([
            [1, 0], [2, 0], [1, 0], [3, 0], [5, 0],
            [2, 1], [1, 0], [4, 0], [2, 0], [1, 1]
        ])
        self.model.fit(X_train)

    def analyze_behavior(self, host, volume, is_off_hours=0):
        """
        Detects behavioral anomalies and insider threats using scikit-learn IsolationForest.
        """
        # Format incoming feature vector
        features = np.array([[volume, is_off_hours]])
        
        # Predict: -1 indicates anomaly/outlier, 1 indicates normal behavior
        prediction = self.model.predict(features)[0]
        raw_score = self.model.score_samples(features)[0]
        
        # Normalize score into a readable deviation metric (Z-score equivalent)
        z_score = round(abs(float(raw_score)) * 5, 2)
        
        is_anomaly = True if prediction == -1 else False
        detection_label = "Standard Activity"

        if is_anomaly:
            if volume > 40:
                detection_label = "INSIDER THREAT: Mass Data Exfiltration Anomaly (IsolationForest ML)"
            else:
                detection_label = "APT / Behavioral Deviation Detected (ML Outlier)"

        return z_score, is_anomaly, detection_label
