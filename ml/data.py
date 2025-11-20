import json
import pandas as pd
from pathlib import Path
from typing import Tuple, Optional
import numpy as np

def load_urls_with_labels(path: str='tests/urls.json') -> pd.DataFrame:
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    return pd.DataFrame(data)

def load_url_dataset_csv(path: str='dataset/URL_dataset.csv', sample_size: Optional[int]=None, balance_classes: bool=True, random_state: int=42) -> pd.DataFrame:
    print(f'Loading dataset from {path}...')
    df = pd.read_csv(path)
    if 'type' in df.columns:
        df = df.rename(columns={'type': 'label'})
    df['label'] = df['label'].str.lower()
    df['label'] = df['label'].replace({'legitimate': 'safe', 'benign': 'safe', 'malicious': 'phishing'})
    df = df[df['label'].isin(['safe', 'phishing'])].copy()
    print(f'Total samples: {len(df)}')
    print(f"Label distribution:\n{df['label'].value_counts()}")
    if balance_classes:
        safe_count = (df['label'] == 'safe').sum()
        phishing_count = (df['label'] == 'phishing').sum()
        if safe_count > phishing_count * 1.5:
            df_safe = df[df['label'] == 'safe'].sample(n=int(phishing_count * 1.2), random_state=random_state)
            df_phishing = df[df['label'] == 'phishing']
            df = pd.concat([df_safe, df_phishing], ignore_index=True)
            print(f'\nBalanced dataset to {len(df)} samples')
            print(f"New distribution:\n{df['label'].value_counts()}")
    if sample_size and sample_size < len(df):
        df = df.groupby('label', group_keys=False).apply(lambda x: x.sample(n=min(len(x), sample_size // 2), random_state=random_state)).reset_index(drop=True)
        print(f'\nSampled to {len(df)} samples')
        print(f"Sampled distribution:\n{df['label'].value_counts()}")
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)
    return df

def split_train_test(df: pd.DataFrame, test_size: float=0.2, random_state: int=42) -> Tuple[pd.DataFrame, pd.DataFrame]:
    from sklearn.model_selection import train_test_split
    (train_df, test_df) = train_test_split(df, test_size=test_size, random_state=random_state, stratify=df['label'])
    print(f'\nTrain set: {len(train_df)} samples')
    print(f'Test set: {len(test_df)} samples')
    print(f"\nTrain distribution:\n{train_df['label'].value_counts()}")
    print(f"Test distribution:\n{test_df['label'].value_counts()}")
    return (train_df.reset_index(drop=True), test_df.reset_index(drop=True))