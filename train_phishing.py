#!/usr/bin/env python3
"""
Phishing Website Detector – Training Script
--------------------------------------------
Loads the phishing dataset, performs feature scaling,
trains a Random Forest classifier, evaluates it,
and saves the model and scaler for later use.
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')

# ===================== CONFIGURATION =====================
DATA_PATH = 'data/phishing_data.csv'
MODEL_DIR = 'models'
MODEL_PATH = os.path.join(MODEL_DIR, 'phishing_model.pkl')
SCALER_PATH = os.path.join(MODEL_DIR, 'scaler.pkl')
TEST_SIZE = 0.2
RANDOM_STATE = 42
# =========================================================

def create_directory(path):
    """Create directory if it doesn't exist."""
    if not os.path.exists(path):
        os.makedirs(path)
        print(f"Created directory: {path}")

def load_data(file_path):
    """Load dataset, drop non‑feature columns, separate X and y."""
    df = pd.read_csv(file_path)
    print(f"Dataset shape: {df.shape}")
    print(f"Columns: {list(df.columns)}")
    
    # Drop the 'id' column – it is not a feature
    if 'id' in df.columns:
        df = df.drop(columns=['id'])
        print("Dropped 'id' column.")
    
    # Separate features and target
    X = df.drop(columns=['CLASS_LABEL'])
    y = df['CLASS_LABEL']
    print(f"Features shape: {X.shape}")
    print(f"Target distribution:\n{y.value_counts()}")
    return X, y

def main():
    print("=" * 60)
    print("PHISHING WEBSITE DETECTION – TRAINING PIPELINE")
    print("=" * 60)
    
    # 1. Create output directory
    create_directory(MODEL_DIR)
    
    # 2. Load data
    X, y = load_data(DATA_PATH)
    
    # 3. Train / test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y          # keep class proportions
    )
    print(f"\nTraining set size: {X_train.shape[0]} samples")
    print(f"Test set size:     {X_test.shape[0]} samples")
    
    # 4. Feature scaling
    print("\n[1] Fitting StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("    Scaling done.")
    
    # 5. Train classifier
    print("\n[2] Training Random Forest classifier...")
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=RANDOM_STATE,
        n_jobs=-1
    )
    clf.fit(X_train_scaled, y_train)
    print("    Training finished.")
    
    # 6. Evaluate on test set
    print("\n[3] Evaluating on test set...")
    y_pred = clf.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Test Accuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # 7. (Optional) Feature importance
    feature_names = X.columns
    importances = clf.feature_importances_
    top_indices = np.argsort(importances)[-10:]  # top 10
    print("\nTop 10 most important features:")
    for i in top_indices[::-1]:
        print(f"  {feature_names[i]:25s}: {importances[i]:.4f}")
    
    # 8. Save model and scaler
    print("\n[4] Saving model and scaler...")
    joblib.dump(clf, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    print(f"    Model saved to:  {MODEL_PATH}")
    print(f"    Scaler saved to: {SCALER_PATH}")
    
    print("\n" + "=" * 60)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 60)

if __name__ == '__main__':
    main()