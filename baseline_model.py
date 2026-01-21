from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.preprocessing import LabelEncoder
import numpy as np

from utils.logger import logger

class BaselineModel:
    def __init__(self):
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)
        self.encoders = {}

    def train(self, X_train, y_train):
        """
        Trains the Random Forest model. 
        Need to handle categorical variables first.
        """
        X_train_encoded = X_train.copy()
        for col in X_train_encoded.columns:
            if X_train_encoded[col].dtype == 'object':
                le = LabelEncoder()
                X_train_encoded[col] = le.fit_transform(X_train_encoded[col].astype(str))
                self.encoders[col] = le
        
        self.clf.fit(X_train_encoded, y_train)

    def predict(self, X_test):
        """
        Predicts labels for test set.
        """
        X_test_encoded = X_test.copy()
        for col in X_test_encoded.columns:
            if col in self.encoders:
                # Handle unseen labels by assigning a default or mode
                le = self.encoders[col]
                # Helper to transform safe
                X_test_encoded[col] = X_test_encoded[col].astype(str).map(
                    lambda s: le.transform([s])[0] if s in le.classes_ else -1
                )
        
        # Log the first few inputs for demonstration (avoid spamming everything if huge)
        # For this demo scale (sample_size=10), logging all is fine.
        try:
             for i in range(min(5, len(X_test_encoded))):
                 row_vals = X_test_encoded.iloc[i].values.tolist()
                 logger.log(
                     model_type="RandomForest", 
                     input_type="Feature Vector (Encoded)", 
                     input_data=f"{row_vals}\n(Cols: {list(X_test_encoded.columns)})"
                 )
        except Exception as e:
            print(f"Logging error: {e}")

        return self.clf.predict(X_test_encoded)

    def evaluate(self, X_test, y_test):
        y_pred = self.predict(X_test)
        
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, pos_label=1, average='binary', zero_division=0)
        rec = recall_score(y_test, y_pred, pos_label=1, average='binary', zero_division=0)
        f1 = f1_score(y_test, y_pred, pos_label=1, average='binary', zero_division=0)
        
        return {
            "Accuracy": acc,
            "Precision": prec,
            "Recall": rec,
            "F1": f1
        }
