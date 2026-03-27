import pandas as pd
from sklearn.ensemble import IsolationForest

class RealTimeIDSModel:
    def __init__(self, contamination=0.05):
        # contamination represents the theoretical percentage of anomalies in the traffic
        self.model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.is_trained = False
        self.feature_names = None
        
    def train(self, df: pd.DataFrame):
        """
        Trains the unsupervised Isolation Forest to learn the 'baseline' of normal traffic.
        """
        self.feature_names = df.columns.tolist()
        self.model.fit(df)
        self.is_trained = True
        
    def predict(self, df: pd.DataFrame):
        """
        Predicts if a single instance is an anomaly.
        Returns 1 for normal, -1 for anomaly.
        """
        if not self.is_trained:
            raise ValueError("Model is not trained yet!")
        return self.model.predict(df)
