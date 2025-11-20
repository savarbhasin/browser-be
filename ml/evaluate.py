import json
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from be.app.ml.features import extract_features, FEATURE_ORDER
from ml.data import load_url_dataset_csv

def build_dataset(df: pd.DataFrame):
    X = []
    y = []
    print('Extracting features...')
    for (idx, row) in df.iterrows():
        if idx % 1000 == 0:
            print(f'  Processed {idx}/{len(df)} URLs...')
        try:
            feats = extract_features(row['url'])
            X.append([feats[k] for k in FEATURE_ORDER])
            y.append(1 if row['label'] == 'phishing' else 0)
        except:
            continue
    return (np.array(X, dtype=float), np.array(y, dtype=int))

def main():
    print('=' * 60)
    print('Model Evaluation')
    print('=' * 60)
    if not Path('models/url_model.joblib').exists():
        print('\nError: No trained model found!')
        print('Please run: python -m ml.train')
        return
    print('\nLoading model...')
    bundle = joblib.load('models/url_model.joblib')
    model = bundle['model']
    threshold = bundle.get('threshold', 0.5)
    model_name = bundle.get('model_name', 'Unknown')
    print(f'  Model: {model_name}')
    print(f'  Threshold: {threshold:.4f}')
    print('\nLoading test dataset...')
    df = load_url_dataset_csv(path='dataset/URL_dataset.csv', sample_size=10000, balance_classes=True)
    (X, y) = build_dataset(df)
    print(f'\nEvaluating on {len(X)} samples...')
    probs = model.predict_proba(X)[:, 1]
    y_pred = (probs >= threshold).astype(int)
    auc = roc_auc_score(y, probs)
    print(f"\n{'=' * 60}")
    print('Results:')
    print(f"{'=' * 60}")
    print(f'AUC: {auc:.4f}')
    print(f'\nClassification Report:')
    print(classification_report(y, y_pred, target_names=['Safe', 'Phishing']))
    print(f'\nConfusion Matrix:')
    cm = confusion_matrix(y, y_pred)
    print(f'  TN: {cm[0, 0]:5d}  FP: {cm[0, 1]:5d}')
    print(f'  FN: {cm[1, 0]:5d}  TP: {cm[1, 1]:5d}')
    Path('reports').mkdir(exist_ok=True)
    res = {'model_name': model_name, 'threshold': float(threshold), 'auc': float(auc), 'samples_evaluated': len(X), 'confusion_matrix': cm.tolist(), 'report': classification_report(y, y_pred, target_names=['Safe', 'Phishing'], output_dict=True)}
    Path('reports/eval.json').write_text(json.dumps(res, indent=2))
    print(f'\nSaved results to reports/eval.json')
if __name__ == '__main__':
    main()