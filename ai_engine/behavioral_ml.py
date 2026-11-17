import numpy as np
import logging
from sklearn.ensemble import IsolationForest

logger = logging.getLogger("SOAR-BehavioralML")

class BehavioralAnomalyDetector:
    def __init__(self):
        # Unsupervised ML Model for Behavioral Anomaly / Insider Threat Detection
        self.model = IsolationForest(contamination=0.05, random_state=42)

        # === BIG DATA UPGRADE (10,000 Baseline Events) ===
        np.random.seed(42)
        
        # Generate normal behaviour: volume 1 to 20 files, no off-hours (9,500 samples)
        normal_volume = np.random.randint(1, 20, 9500)
        normal_off_hours = np.zeros(9500)
        
        # Generate anomalous behaviour: high volume, mostly off-hours (500 samples)
        anomaly_volume = np.random.randint(50, 1000, 500)
        anomaly_off_hours = np.random.randint(0, 2, 500)
        
        volumes = np.concatenate((normal_volume, anomaly_volume))
        off_hours = np.concatenate((normal_off_hours, anomaly_off_hours))
        
        X_train = np.column_stack((volumes, off_hours))
        # ====================================================

        self.model.fit(X_train)
        logger.info(f"[BEHAVIORAL PROOF] IsolationForest trained on {len(X_train)} baseline user events.")

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
