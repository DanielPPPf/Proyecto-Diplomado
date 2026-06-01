"""Genera notebooks/03_Modelo2_Autoencoder.ipynb (deteccion de anomalias)."""
import nbformat as nbf
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

nb = new_notebook()
c = []

c.append(new_markdown_cell(
"""# Modelo 2 — Autoencoder de secuencias para detección de anomalías
## Encontrar la sesión "rara" entre los ataques automatizados

El EDA mostró que las sesiones activas son casi todas automatizadas: ejecutan
payloads tipo Mirai (`cd /tmp; wget ...; chmod; sh ...`) que se repiten desde
muchas IPs. La idea de este modelo:

> Entrenar un **autoencoder a nivel de carácter** que aprenda a reconstruir esas
> secuencias de comandos "normales" (automatizadas). Una sesión que el modelo
> **no logre reconstruir bien** (alto error de reconstrucción) es *atípica* —
> candidata a actividad humana o a una campaña novedosa.

Es detección de anomalías **no supervisada**: no necesitamos etiquetas humano/bot,
que justamente no tenemos."""))

c.append(new_code_cell(
"""import os
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

sns.set_theme(style="whitegrid")
plt.rcParams["figure.dpi"] = 110
FIG = "../reports/figures"
np.random.seed(42); tf.random.set_seed(42)

df = pd.read_parquet("../data/processed/sessions.parquet")
act = df[df.n_commands > 0].copy().reset_index(drop=True)
print(f"Sesiones activas (con comandos): {len(act)}")"""))

c.append(new_markdown_cell(
"""## 1. Codificación a nivel de carácter

Convertimos cada secuencia de comandos en una secuencia de enteros (un entero por
carácter), truncada/rellenada a longitud fija `L=400`. El índice 0 se reserva como
*padding*."""))

c.append(new_code_cell(
"""L = 400
# vocabulario de caracteres (0 = PAD)
chars = sorted({ch for s in act["commands"] for ch in s})
stoi = {ch: i + 1 for i, ch in enumerate(chars)}
VOCAB = len(stoi) + 1
print(f"Tamaño de vocabulario (incl. PAD): {VOCAB}")

def encode(s):
    ids = [stoi[ch] for ch in s[:L]]
    return ids + [0] * (L - len(ids))

X = np.array([encode(s) for s in act["commands"]], dtype=np.int32)
print("Matriz de secuencias:", X.shape)"""))

c.append(new_markdown_cell(
"""## 2. Arquitectura del autoencoder (Conv1D)

- **Encoder:** Embedding de caracteres → dos bloques Conv1D + MaxPooling que
  comprimen la secuencia (400 → 100) en una representación latente.
- **Decoder:** Conv1D + UpSampling que reconstruyen la longitud original y
  predicen, en cada posición, una distribución softmax sobre el vocabulario.
- **Pérdida:** entropía cruzada categórica dispersa (reconstruir el carácter
  original en cada posición)."""))

c.append(new_code_cell(
"""def build_autoencoder(L, vocab, emb=32):
    inp = keras.Input(shape=(L,))
    x = layers.Embedding(vocab, emb)(inp)
    # encoder
    x = layers.Conv1D(64, 5, activation="relu", padding="same")(x)
    x = layers.MaxPooling1D(2)(x)                 # 400 -> 200
    x = layers.Conv1D(32, 5, activation="relu", padding="same")(x)
    x = layers.MaxPooling1D(2)(x)                 # 200 -> 100  (cuello de botella)
    # decoder
    x = layers.Conv1D(32, 5, activation="relu", padding="same")(x)
    x = layers.UpSampling1D(2)(x)                 # 100 -> 200
    x = layers.Conv1D(64, 5, activation="relu", padding="same")(x)
    x = layers.UpSampling1D(2)(x)                 # 200 -> 400
    out = layers.Conv1D(vocab, 1, activation="softmax")(x)
    m = keras.Model(inp, out)
    m.compile(optimizer=keras.optimizers.Adam(1e-3),
              loss="sparse_categorical_crossentropy")
    return m

ae = build_autoencoder(L, VOCAB)
ae.summary()"""))

c.append(new_markdown_cell(
"""## 3. Entrenamiento

Reservamos un 15% de validación solo para monitorear con *early stopping* y evitar
que el modelo memorice. El objetivo de reconstrucción es la propia secuencia de
entrada (autoencoder)."""))

c.append(new_code_cell(
"""idx = np.random.permutation(len(X))
n_val = int(0.15 * len(X))
val_idx, tr_idx = idx[:n_val], idx[n_val:]
X_tr, X_val = X[tr_idx], X[val_idx]

es = keras.callbacks.EarlyStopping(monitor="val_loss", patience=12,
                                   restore_best_weights=True)
hist = ae.fit(X_tr, X_tr, validation_data=(X_val, X_val),
              epochs=120, batch_size=32, callbacks=[es], verbose=2)

plt.figure(figsize=(7,4))
plt.plot(hist.history["loss"], label="train")
plt.plot(hist.history["val_loss"], label="val")
plt.title("Pérdida de reconstrucción"); plt.xlabel("época")
plt.ylabel("sparse CE"); plt.legend()
plt.tight_layout(); plt.savefig(f"{FIG}/09_m2_loss.png"); plt.show()"""))

c.append(new_markdown_cell(
"""## 4. Error de reconstrucción por sesión

Para cada sesión calculamos el error medio de reconstrucción **solo sobre las
posiciones reales** (ignorando el padding). Un error alto = el autoencoder no
supo reproducir esa secuencia = sesión atípica."""))

c.append(new_code_cell(
"""probs = ae.predict(X, batch_size=64, verbose=0)        # (N, L, VOCAB)
eps = 1e-9
true_p = np.take_along_axis(probs, X[..., None], axis=2)[..., 0]  # prob del char real
ce = -np.log(true_p + eps)                              # CE por posición
mask = (X != 0).astype(np.float32)                      # ignora PAD
recon_err = (ce * mask).sum(1) / mask.sum(1)            # error medio por sesión
act["recon_err"] = recon_err

print(act["recon_err"].describe(percentiles=[.5,.9,.95,.99]).round(3))

plt.figure(figsize=(8,4))
plt.hist(recon_err, bins=50, color="#4C72B0")
thr = np.percentile(recon_err, 95)
plt.axvline(thr, color="red", ls="--", label=f"umbral p95 = {thr:.2f}")
plt.title("Distribución del error de reconstrucción por sesión")
plt.xlabel("error medio de reconstrucción"); plt.ylabel("nº sesiones"); plt.legend()
plt.tight_layout(); plt.savefig(f"{FIG}/10_m2_error_hist.png"); plt.show()
print(f"\\nSesiones marcadas como anómalas (error > p95): {(recon_err > thr).sum()}")"""))

c.append(new_markdown_cell(
"""## 5. ¿Qué aprendió el modelo? Normales vs. anómalas

Contrastamos las sesiones que el autoencoder reconstruye **mejor** (las
automatizadas típicas) con las que reconstruye **peor** (las atípicas)."""))

c.append(new_code_cell(
"""def short(s, n=140): return (s[:n] + " …") if len(s) > n else s

print("="*80)
print("SESIONES MEJOR RECONSTRUIDAS (automatizadas típicas, error bajo):")
print("="*80)
for _, r in act.nsmallest(5, "recon_err").iterrows():
    print(f"[err={r.recon_err:.2f} | {r.n_commands} cmds | gap_mean={r.gap_mean:.3f}s]")
    print(f"   {short(r.commands)}\\n")

print("="*80)
print("SESIONES MÁS ANÓMALAS (error alto = candidatas humanas/novedosas):")
print("="*80)
for _, r in act.nlargest(10, "recon_err").iterrows():
    print(f"[err={r.recon_err:.2f} | {r.n_commands} cmds | gap_mean={r.gap_mean:.3f}s | {r.country}]")
    print(f"   {short(r.commands)}\\n")"""))

c.append(new_markdown_cell(
"""## 6. Validación cruzada con la heurística de ritmo

No tenemos etiquetas humano/bot, pero sí una **pista independiente**: el ritmo
entre comandos (`gap_mean`). Un humano teclea con pausas (>2s). Si las sesiones
con error de reconstrucción alto tienden también a tener ritmo lento, ambas
señales —que el modelo *nunca vio el tiempo*— estarían apuntando a lo mismo,
reforzando que detectan actividad no automatizada."""))

c.append(new_code_cell(
"""sub = act[act.n_commands >= 2].copy()
sub["anomala"] = sub["recon_err"] > np.percentile(act["recon_err"], 95)
sub["ritmo_humano"] = sub["gap_mean"] > 2.0

ct = pd.crosstab(sub["anomala"], sub["ritmo_humano"],
                 rownames=["¿anómala (AE)?"], colnames=["¿ritmo humano (>2s)?"])
print(ct, "\\n")

# correlación error vs ritmo
corr = sub[["recon_err", "gap_mean"]].corr().iloc[0,1]
print(f"Correlación error_reconstrucción vs gap_mean: {corr:.3f}")

plt.figure(figsize=(7,5))
plt.scatter(sub["gap_mean"].clip(upper=10), sub["recon_err"],
            c=sub["anomala"].map({True:"#C44E52", False:"#4C72B0"}), alpha=0.6)
plt.axvline(2.0, color="green", ls="--", lw=0.8, label="ritmo humano (2s)")
plt.axhline(np.percentile(act["recon_err"],95), color="red", ls="--", lw=0.8, label="umbral anomalía (p95)")
plt.xlabel("gap_mean entre comandos (s, clip 10)")
plt.ylabel("error de reconstrucción (AE)")
plt.title("Anomalía (AE, solo comandos) vs. ritmo (tiempo)")
plt.legend(); plt.tight_layout(); plt.savefig(f"{FIG}/11_m2_cruce.png"); plt.show()"""))

c.append(new_markdown_cell(
"""## 7. Conclusiones del Modelo 2

- El autoencoder aprende a reconstruir con bajo error los **payloads automatizados
  repetidos** (droppers Mirai), confirmando que ese es el patrón dominante.
- Las sesiones con **alto error de reconstrucción** son las atípicas: comandos
  poco frecuentes, estructura inusual o exploración no estándar — justo las
  candidatas a intervención humana o campañas nuevas.
- El cruce con la heurística de ritmo (señal temporal independiente, que el modelo
  no usó) permite valorar si ambas perspectivas coinciden al señalar sesiones no
  automatizadas.

**Cierre del enfoque combinado:** el Modelo 1 filtra, en la fase de login, qué
sesiones escalarán a ejecutar comandos; el Modelo 2 analiza *qué hacen* esas
sesiones y aísla las raras para revisión humana del SOC. Juntos cubren el objetivo
de priorizar la respuesta a incidentes."""))

c.append(new_code_cell(
"""os.makedirs("../models", exist_ok=True)
ae.save("../models/modelo2_autoencoder.keras")
# guardamos también el ranking de anomalías para el reporte
act[["session_id","country","n_commands","gap_mean","recon_err","commands"]] \\
   .sort_values("recon_err", ascending=False) \\
   .to_csv("../reports/anomalias_top.csv", index=False)
print("Autoencoder guardado y ranking de anomalías exportado a reports/anomalias_top.csv")"""))

nb["cells"] = c
nb["metadata"] = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python"},
}
with open("notebooks/03_Modelo2_Autoencoder.ipynb", "w") as f:
    nbf.write(nb, f)
print("Notebook creado: notebooks/03_Modelo2_Autoencoder.ipynb")
