"""
Exporta los artefactos necesarios para inferencia en vivo (fuera del notebook):
- Modelo 2: vocabulario de caracteres (stoi), longitud L y umbral de anomalía.
- Modelo 1: columnas, escalado y mapas de categorías top-N del preprocesamiento.

Se guardan en models/inference_artifacts/ para que el servicio del laboratorio
(lab/inference/infer_service.py) reproduzca exactamente el preprocesamiento de
entrenamiento sin depender de los notebooks.
"""
import os
import json
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "models", "inference_artifacts")
os.makedirs(OUT, exist_ok=True)

df = pd.read_parquet(os.path.join(ROOT, "data", "processed", "sessions.parquet"))
act = df[df.n_commands > 0].copy()

# ---------- Modelo 2: vocabulario + umbral ----------
L = 400
chars = sorted({ch for s in act["commands"] for ch in s})
stoi = {ch: i + 1 for i, ch in enumerate(chars)}  # 0 = PAD

# umbrales de anomalía del error de reconstrucción (calculado en el notebook):
#   p95 -> "revisar" (suave) ; p99 -> "claramente novedoso" (duro)
anom_csv = os.path.join(ROOT, "reports", "anomalias_top.csv")
err = pd.read_csv(anom_csv)["recon_err"]
threshold_review = float(np.percentile(err, 95))
threshold_novel = float(np.percentile(err, 99))

with open(os.path.join(OUT, "m2_vocab.json"), "w") as f:
    json.dump({"stoi": stoi, "L": L,
               "threshold": threshold_review,          # compat
               "threshold_review": threshold_review,
               "threshold_novel": threshold_novel}, f)
print(f"M2: vocab={len(stoi)} chars, L={L}, "
      f"umbral revisar(p95)={threshold_review:.3f}, novedoso(p99)={threshold_novel:.3f}")

# ---------- Modelo 1: preprocesamiento ----------
num_cols = ["duration", "n_login_ok", "n_login_fail", "n_login_total"]

def topn(series, n):
    s = series.fillna("NA")
    top = s.value_counts().head(n).index.tolist()
    return s.where(s.isin(top), "OTHER"), top

sensor_c, sensor_top = topn(df["sensor"], 3)
country_c, country_top = topn(df["country"], 20)
client_c, client_top = topn(df["client_version"], 20)

cat = pd.DataFrame({"sensor": sensor_c, "country": country_c, "client_version": client_c})
X_cat = pd.get_dummies(cat, prefix=cat.columns.tolist())
dummy_cols = X_cat.columns.tolist()

# escalado (refit sobre todo el conjunto para el artefacto desplegable)
X_num = np.log1p(df[num_cols].clip(lower=0)).values
X = np.hstack([X_num, X_cat.values.astype(float)])
mean = X.mean(0)
std = X.std(0)
std[std == 0] = 1.0

m1 = {
    "num_cols": num_cols,
    "sensor_top": sensor_top,
    "country_top": country_top,
    "client_top": client_top,
    "dummy_cols": dummy_cols,
    "scaler_mean": mean.tolist(),
    "scaler_std": std.tolist(),
    "n_features": X.shape[1],
}
with open(os.path.join(OUT, "m1_preprocess.json"), "w") as f:
    json.dump(m1, f)
print(f"M1: {X.shape[1]} features ({len(num_cols)} num + {len(dummy_cols)} one-hot)")
print(f"Artefactos guardados en {OUT}")
