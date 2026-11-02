import numpy as np
from sklearn.linear_model import LogisticRegression

class RiskScorer:
    def __init__(self):
        # Supervised ML Classifier for Risk Assessment
        self.classifier = LogisticRegression()
        
        # Training features: [is_ransomware, is_misp_match, is_anomaly, normalized_volume]
        X_train = np.array([
            [0, 0, 0, 0.05], # Normal low risk
            [1, 1, 1, 0.90], # Critical ransomware + MISP match + anomaly
            [0, 1, 0, 0.20], # Medium MISP match
            [1, 0, 1, 0.80], # High ransomware + anomaly
            [0, 0, 1, 0.50]  # Insider threat anomaly
        ])
        y_train = np.array([0, 1, 0, 1, 1]) # 1 = High/Critical Risk, 0 = Low/Medium Risk
        
        self.classifier.fit(X_train, y_train)

    def calculate_risk(self, event_type, threat_matched, is_anomaly, volume):
        """
        Evaluates risk score and severity using a scikit-learn probability model.
        """
        is_ransomware = 1 if event_type == "Ransomware" else 0
        misp_flag = 1 if threat_matched else 0
        anomaly_flag = 1 if is_anomaly else 0
        norm_volume = min(volume / 100.0, 1.0)

        features = np.array([[is_ransomware, misp_flag, anomaly_flag, norm_volume]])
        
        # Predict probability of high risk from scikit-learn
        risk_probability = self.classifier.predict_proba(features)[0][1]
        score = int(risk_probability * 100)

        # Domain heuristic safety overrides for critical security events
        if event_type == "Ransomware" or threat_matched:
            score = max(score, 75)
        if is_anomaly and event_type == "Insider Threat":
            score = max(score, 85)

        score = min(score, 100)

        # Automated Severity Assessment Grading
        if score >= 85:
            severity = "CRITICAL"
        elif score >= 60:
            severity = "HIGH"
        elif score >= 35:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return score, severity
