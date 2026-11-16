"""Demo detector (stand-in for Phases 6-7): features → out-of-fold label agreement + outliers.

* Features: tabular columns (standardized numerics, one-hot low-cardinality categories),
  hashed TF-IDF for text, downscaled pixels + PCA for images.
* Label agreement: a logistic regression predicts every record's label *without seeing it*
  (stratified K-fold). Confident-learning rule: a record is a label suspect when another class
  clears that class's own average confidence and the given label's probability is low.
* Outliers: Isolation Forest rank, blended in with a small weight.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy import sparse
from sklearn.decomposition import PCA, TruncatedSVD
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict

from poisonlens.core.config import ScanConfig


@dataclass
class DetectResult:
    record_ids: list[str]
    score: np.ndarray  # 0..1 suspicion
    p_given: np.ndarray  # out-of-fold probability of the given label (nan when not scored)
    predicted: list[str | None]
    label_suspect: np.ndarray  # bool
    outlier: np.ndarray  # 0..1 rank
    oof_accuracy: float | None
    method: str
    notes: list[str] = field(default_factory=list)


def tabular_matrix(feats: pd.DataFrame, text_column: str | None, cfg: ScanConfig) -> sparse.csr_matrix:
    blocks: list[sparse.csr_matrix] = []
    for col in feats.columns:
        s = feats[col]
        if col == text_column:
            blocks.append(text_matrix(s, cfg))
        elif pd.api.types.is_bool_dtype(s) or pd.api.types.is_numeric_dtype(s):
            v = pd.to_numeric(s, errors="coerce").astype(float)
            v = v.fillna(v.median() if v.notna().any() else 0.0)
            sd = float(v.std()) or 1.0
            blocks.append(sparse.csr_matrix(((v - v.mean()) / sd).to_numpy()[:, None]))
        else:
            st = s.astype("string").fillna("<na>")
            if st.nunique() <= 50:
                blocks.append(sparse.csr_matrix(pd.get_dummies(st).to_numpy(dtype=float)))
            elif st.str.len().mean() >= 20:  # free text that was not chosen as the text column
                blocks.append(text_matrix(s, cfg))
            # else: identifier-like column (names, ids) — not a feature
    if not blocks:
        raise ValueError("no usable feature columns")
    return sparse.hstack(blocks).tocsr()


def text_matrix(texts: pd.Series, cfg: ScanConfig) -> sparse.csr_matrix:
    hv = HashingVectorizer(
        n_features=cfg.demo.text_hash_features,
        ngram_range=(1, cfg.features.text_ngram_max),
        alternate_sign=False,
        norm=None,
    )
    counts = hv.transform(texts.fillna("").astype(str).str.slice(0, 20_000))
    return TfidfTransformer(sublinear_tf=True).fit_transform(counts).tocsr()


def _reduce(x: sparse.csr_matrix | np.ndarray, cfg: ScanConfig) -> np.ndarray:
    dims = min(cfg.demo.pca_dims, x.shape[1] - 1, x.shape[0] - 1)
    if dims < 2:
        return sparse.csr_matrix(x).toarray() if sparse.issparse(x) else np.asarray(x)
    if sparse.issparse(x):
        return TruncatedSVD(n_components=dims, random_state=cfg.seed).fit_transform(x)
    return PCA(n_components=dims, random_state=cfg.seed).fit_transform(x)


def detect(
    record_ids: list[str], x: sparse.csr_matrix | np.ndarray, labels: pd.Series, cfg: ScanConfig, method: str
) -> DetectResult:
    n = len(record_ids)
    lab = labels.astype("string").to_numpy()
    p_given = np.full(n, np.nan)
    predicted: list[str | None] = [None] * n
    suspect = np.zeros(n, dtype=bool)
    notes: list[str] = []
    acc: float | None = None

    if method == "image" or (not sparse.issparse(x) and x.shape[1] > cfg.demo.pca_dims):
        x = _reduce(x, cfg)
        method += "+pca"

    known = pd.Series(lab).notna().to_numpy()
    counts = pd.Series(lab[known]).value_counts()
    folds = min(cfg.demo.cv_folds, int(counts.min()) if len(counts) else 0)
    keep_classes = counts[counts >= 2].index
    use = known & pd.Series(lab).isin(keep_classes).to_numpy()
    if len(keep_classes) >= 2 and folds >= 2 and use.sum() >= 10:
        xs = x[use]
        ys = lab[use]
        clf = LogisticRegression(max_iter=2000, C=1.0)
        cv = StratifiedKFold(n_splits=min(folds, cfg.demo.cv_folds), shuffle=True, random_state=cfg.seed)
        proba = cross_val_predict(clf, xs, ys, cv=cv, method="predict_proba")
        classes = np.array(sorted(set(ys)))
        col = {c: i for i, c in enumerate(classes)}
        given_i = np.array([col[y] for y in ys])
        pg = proba[np.arange(len(ys)), given_i]
        # confident-learning per-class thresholds: mean self-confidence of records labelled j
        thr = np.array([proba[given_i == j, j].mean() for j in range(len(classes))])
        pred_i = proba.argmax(1)
        above = proba >= thr[None, :]
        masked = np.where(above, proba, -1.0)
        cl_pred = masked.argmax(1)
        has = above.any(1)
        sus = has & (cl_pred != given_i) & (pg < cfg.demo.label_suspect_prob)
        idx = np.flatnonzero(use)
        p_given[idx] = pg
        suspect[idx] = sus
        for k, i in enumerate(idx):
            predicted[i] = str(classes[pred_i[k]])
        acc = float((pred_i == given_i).mean())
    else:
        notes.append("Label agreement skipped: need at least two classes with two or more records each.")

    try:
        xd = _reduce(x, cfg) if sparse.issparse(x) else np.asarray(x)
        iso = IsolationForest(n_estimators=200, random_state=cfg.seed).fit(xd)
        raw = -iso.score_samples(xd)
        outlier = pd.Series(raw).rank(pct=True).to_numpy()
    except ValueError as e:
        outlier = np.zeros(n)
        notes.append(f"Outlier scoring skipped: {e}")

    w = cfg.demo.outlier_weight
    label_part = np.where(np.isnan(p_given), 0.0, 1.0 - p_given)
    score = (1 - w) * label_part + w * np.where(outlier > 0.9, outlier, 0.0)
    score = np.where(suspect, np.maximum(score, 0.6), np.minimum(score, 0.59))
    return DetectResult(record_ids, score, p_given, predicted, suspect, outlier, acc, method, notes)
