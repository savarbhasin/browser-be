import os
import joblib
import numpy as np
from typing import Dict, Any, Tuple
from pathlib import Path
from .features import FEATURE_ORDER

class UrlModel:

    def __init__(self, model_path: str):
        self.model_path = model_path
        (self.model, self.threshold) = self._load_or_init()

    def _load_or_init(self) -> Tuple[Any, float]:
        if not os.path.isabs(self.model_path):
            app_dir = Path(__file__).parent.parent.parent
            model_path = app_dir / self.model_path
            if not model_path.exists():
                workspace_root = app_dir.parent
                model_path = workspace_root / self.model_path.lstrip('../')
        else:
            model_path = Path(self.model_path)
        if model_path.exists():
            bundle = joblib.load(model_path)
            model = bundle['model']
            threshold = bundle.get('threshold', 0.5)
            return (model, float(threshold))
        raise ValueError(f'Model file not found: {model_path}')

    def _to_matrix(self, feats: Dict[str, Any]):
        return np.array([[feats[k] for k in FEATURE_ORDER]], dtype=float)

    def predict_proba(self, feats: Dict[str, Any]) -> float:
        X = self._to_matrix(feats)
        p = float(self.model.predict_proba(X)[0][1])
        return p