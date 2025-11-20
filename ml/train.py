import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import roc_auc_score, roc_curve, precision_recall_fscore_support, classification_report, confusion_matrix
import matplotlib.pyplot as plt
import time
from be.app.ml.features import extract_features, FEATURE_ORDER
from ml.data import load_url_dataset_csv, split_train_test

def build_dataset(df: pd.DataFrame):
    X = []
    y = []
    print('\nExtracting features from URLs...')
    for (idx, row) in df.iterrows():
        if idx % 10000 == 0:
            print(f'  Processed {idx}/{len(df)} URLs...')
        try:
            feats = extract_features(row['url'])
            X.append([feats[k] for k in FEATURE_ORDER])
            y.append(1 if row['label'] == 'phishing' else 0)
        except Exception as e:
            continue
    print(f'Successfully extracted features from {len(X)} URLs')
    return (np.array(X, dtype=float), np.array(y, dtype=int))

def choose_threshold(y_true, y_prob, target_fp_rate=0.1):
    (fpr, tpr, thr) = roc_curve(y_true, y_prob)
    idx = (fpr <= target_fp_rate).nonzero()[0]
    if len(idx) == 0:
        return 0.5
    return float(thr[idx[-1]])

def evaluate_model(name: str, model, X, y):
    print(f"\n{'=' * 60}")
    print(f'Evaluating: {name}')
    print(f"{'=' * 60}")
    start_time = time.time()
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs = np.zeros_like(y, dtype=float)
    for (fold, (tr, te)) in enumerate(skf.split(X, y), 1):
        print(f'  Fold {fold}/5...')
        model.fit(X[tr], y[tr])
        probs[te] = model.predict_proba(X[te])[:, 1]
    auc = roc_auc_score(y, probs)
    threshold = choose_threshold(y, probs, target_fp_rate=0.1)
    y_pred = (probs >= threshold).astype(int)
    (prec, rec, f1, _) = precision_recall_fscore_support(y, y_pred, average='binary')
    elapsed = time.time() - start_time
    print(f'\n  Results:')
    print(f'    AUC: {auc:.4f}')
    print(f'    Threshold: {threshold:.4f}')
    print(f'    Precision: {prec:.4f}')
    print(f'    Recall: {rec:.4f}')
    print(f'    F1-Score: {f1:.4f}')
    print(f'    Training time: {elapsed:.2f}s')
    return {'name': name, 'model': model, 'auc': auc, 'threshold': threshold, 'precision': prec, 'recall': rec, 'f1': f1, 'probs': probs, 'training_time': elapsed}

def main():
    Path('models').mkdir(exist_ok=True)
    Path('reports').mkdir(exist_ok=True)
    print('=' * 60)
    print('URL Phishing Detection - Model Training')
    print('=' * 60)
    df = load_url_dataset_csv(path='dataset/URL_dataset.csv', sample_size=None, balance_classes=True, random_state=42)
    (train_df, test_df) = split_train_test(df, test_size=0.2, random_state=42)
    print('\n' + '=' * 60)
    print('Feature Extraction')
    print('=' * 60)
    (X_train, y_train) = build_dataset(train_df)
    (X_test, y_test) = build_dataset(test_df)
    print('\n' + '=' * 60)
    print('Model Training & Evaluation')
    print('=' * 60)
    models = [('Logistic Regression', LogisticRegression(max_iter=1000, random_state=42)), ('Random Forest', RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1)), ('Gradient Boosting', GradientBoostingClassifier(n_estimators=100, max_depth=5, random_state=42))]
    results = []
    for (name, model) in models:
        result = evaluate_model(name, model, X_train, y_train)
        results.append(result)
    best_result = max(results, key=lambda x: x['f1'])
    print(f"\n{'=' * 60}")
    print(f"Best Model: {best_result['name']}")
    print(f"  F1-Score: {best_result['f1']:.4f}")
    print(f"  AUC: {best_result['auc']:.4f}")
    print(f"{'=' * 60}")
    print(f'\nTraining best model on full training set...')
    best_model = best_result['model']
    best_model.fit(X_train, y_train)
    print(f'\nEvaluating on held-out test set...')
    y_test_probs = best_model.predict_proba(X_test)[:, 1]
    y_test_pred = (y_test_probs >= best_result['threshold']).astype(int)
    test_auc = roc_auc_score(y_test, y_test_probs)
    (test_prec, test_rec, test_f1, _) = precision_recall_fscore_support(y_test, y_test_pred, average='binary')
    print(f'\nTest Set Results:')
    print(f'  AUC: {test_auc:.4f}')
    print(f'  Precision: {test_prec:.4f}')
    print(f'  Recall: {test_rec:.4f}')
    print(f'  F1-Score: {test_f1:.4f}')
    print(f'\nConfusion Matrix:')
    cm = confusion_matrix(y_test, y_test_pred)
    print(f'  TN: {cm[0, 0]:5d}  FP: {cm[0, 1]:5d}')
    print(f'  FN: {cm[1, 0]:5d}  TP: {cm[1, 1]:5d}')
    print(f'\nSaving model to models/url_model.joblib...')
    joblib.dump({'model': best_model, 'threshold': best_result['threshold'], 'model_name': best_result['name'], 'training_samples': len(X_train), 'test_auc': test_auc, 'test_f1': test_f1}, 'models/url_model.joblib')
    print(f'Generating ROC curve...')
    plt.figure(figsize=(10, 6))
    (fpr, tpr, _) = roc_curve(y_test, y_test_probs)
    plt.plot(fpr, tpr, label=f"{best_result['name']} (AUC={test_auc:.3f})", linewidth=2)
    plt.plot([0, 1], [0, 1], 'k--', label='Random')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve - Test Set')
    plt.legend(loc='lower right')
    plt.grid(alpha=0.3)
    plt.savefig('reports/roc_curve.png', dpi=160, bbox_inches='tight')
    print(f'Saved ROC curve to reports/roc_curve.png')
    report = {'model_name': best_result['name'], 'training_samples': len(X_train), 'test_samples': len(X_test), 'threshold': float(best_result['threshold']), 'cv_auc': float(best_result['auc']), 'cv_f1': float(best_result['f1']), 'test_auc': float(test_auc), 'test_precision': float(test_prec), 'test_recall': float(test_rec), 'test_f1': float(test_f1), 'confusion_matrix': cm.tolist(), 'all_models': [{'name': r['name'], 'auc': float(r['auc']), 'f1': float(r['f1']), 'threshold': float(r['threshold'])} for r in results]}
    Path('reports/metrics.json').write_text(json.dumps(report, indent=2))
    print(f'Saved metrics to reports/metrics.json')
    print(f"\n{'=' * 60}")
    print('Training Complete!')
    print(f"{'=' * 60}")
if __name__ == '__main__':
    main()