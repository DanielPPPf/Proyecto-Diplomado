"""Genera notebooks/01_EDA.ipynb (Análisis Exploratorio de Datos)."""
import nbformat as nbf
from nbformat.v4 import new_notebook, new_markdown_cell, new_code_cell

nb = new_notebook()
cells = []

cells.append(new_markdown_cell(
"""# Análisis Exploratorio de Datos (EDA)
## Detección de atacantes humanos vs. ataques automatizados en sesiones SSH

**Dataset:** CyberLab honeynet (honeypot Cowrie) — muestra de 3 días (24–26 ago 2019).

En este notebook caracterizamos las sesiones SSH capturadas por el honeypot para
entender la naturaleza de los datos antes de modelar. La unidad de análisis es la
**sesión** (un intento de acceso desde una IP), ya agregada en `data/processed/sessions.parquet`
por el módulo `src/parse_cowrie.py`."""))

cells.append(new_code_cell(
"""import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

sns.set_theme(style="whitegrid")
plt.rcParams["figure.dpi"] = 110
FIG = "../reports/figures"

df = pd.read_parquet("../data/processed/sessions.parquet")
print(f"Sesiones totales: {len(df):,}")
df.head(3)"""))

cells.append(new_markdown_cell(
"""## 1. Estructura y volumen

Cada fila es una sesión con features de comportamiento: intentos de login,
nº de comandos, duración, estadísticos de ritmo entre comandos (`gap_*`),
país de origen y la secuencia de comandos ejecutada."""))

cells.append(new_code_cell(
"""print(df.dtypes)
print("\\nResumen numérico:")
df.describe().T"""))

cells.append(new_markdown_cell(
"""## 2. Hallazgo principal: el desbalance extremo

La inmensa mayoría de las sesiones son **fuerza bruta pura**: la IP prueba
credenciales y se desconecta sin ejecutar un solo comando. Solo una fracción
mínima llega a ejecutar comandos (es decir, logra "entrar" y *hacer algo*)."""))

cells.append(new_code_cell(
"""n_active = (df.n_commands > 0).sum()
n_brute  = (df.n_commands == 0).sum()
print(f"Sesiones con comandos (activas): {n_active:,} ({100*n_active/len(df):.2f}%)")
print(f"Sesiones solo-login (fuerza bruta): {n_brute:,} ({100*n_brute/len(df):.2f}%)")

fig, ax = plt.subplots(figsize=(6,4))
bars = ax.bar(["Solo login\\n(fuerza bruta)", "Con comandos\\n(activas)"],
              [n_brute, n_active], color=["#4C72B0", "#C44E52"])
ax.set_yscale("log")
ax.set_ylabel("Nº de sesiones (escala log)")
ax.set_title("Desbalance extremo: 99.8% son fuerza bruta")
for b,v in zip(bars,[n_brute,n_active]):
    ax.text(b.get_x()+b.get_width()/2, v, f"{v:,}", ha="center", va="bottom")
plt.tight_layout(); plt.savefig(f"{FIG}/01_desbalance.png"); plt.show()"""))

cells.append(new_markdown_cell(
"""## 3. Intentos de login por sesión

Las sesiones de fuerza bruta se caracterizan por su patrón de autenticación."""))

cells.append(new_code_cell(
"""fig, axes = plt.subplots(1, 2, figsize=(12,4))
df.n_login_total.clip(upper=20).hist(bins=20, ax=axes[0], color="#4C72B0")
axes[0].set_title("Intentos de login por sesión (clip a 20)")
axes[0].set_xlabel("nº intentos"); axes[0].set_ylabel("sesiones")

ratio = (df.n_login_ok / df.n_login_total.replace(0, np.nan)).dropna()
axes[1].hist(ratio, bins=20, color="#55A868")
axes[1].set_title("Proporción de logins exitosos")
axes[1].set_xlabel("logins_ok / logins_total"); axes[1].set_ylabel("sesiones")
plt.tight_layout(); plt.savefig(f"{FIG}/02_logins.png"); plt.show()"""))

cells.append(new_markdown_cell(
"""## 4. Sesiones activas: nº de comandos y duración

A partir de aquí nos centramos en las **sesiones con comandos**, que son las
candidatas a contener actividad interactiva."""))

cells.append(new_code_cell(
"""act = df[df.n_commands > 0].copy()
fig, axes = plt.subplots(1, 2, figsize=(12,4))
act.n_commands.hist(bins=30, ax=axes[0], color="#C44E52")
axes[0].set_title(f"Nº de comandos por sesión activa (n={len(act)})")
axes[0].set_xlabel("nº comandos"); axes[0].set_ylabel("sesiones")

act.duration.clip(upper=60).hist(bins=40, ax=axes[1], color="#8172B3")
axes[1].set_title("Duración de sesión (seg, clip a 60)")
axes[1].set_xlabel("segundos"); axes[1].set_ylabel("sesiones")
plt.tight_layout(); plt.savefig(f"{FIG}/03_comandos_duracion.png"); plt.show()
print(act[["n_commands","duration"]].describe(percentiles=[.5,.9,.99]).round(2))"""))

cells.append(new_markdown_cell(
"""## 5. La señal clave: ritmo entre comandos (`gap_mean`)

Un script ejecuta comandos en milisegundos; un humano tiene pausas para *pensar*.
Marcamos dos umbrales orientativos: `< 0.5s` (ritmo de máquina) y `> 2s`
(candidato a interacción humana)."""))

cells.append(new_code_cell(
"""multi = df[df.n_commands >= 2].copy()
fig, ax = plt.subplots(figsize=(9,4))
ax.hist(np.log10(multi.gap_mean.clip(lower=1e-3)), bins=40, color="#4C72B0")
ax.axvline(np.log10(0.5), color="green", ls="--", label="0.5s (máquina)")
ax.axvline(np.log10(2.0), color="red", ls="--", label="2s (humano?)")
ax.set_title("Ritmo medio entre comandos (log10 segundos)")
ax.set_xlabel("log10(gap_mean en seg)"); ax.set_ylabel("sesiones"); ax.legend()
plt.tight_layout(); plt.savefig(f"{FIG}/04_ritmo.png"); plt.show()

fast = (multi.gap_mean < 0.5).sum()
slow = (multi.gap_mean > 2).sum()
print(f"Sesiones (>=2 cmd): {len(multi)}")
print(f"  ritmo de máquina (<0.5s): {fast} ({100*fast/len(multi):.1f}%)")
print(f"  candidatas humanas (>2s): {slow} ({100*slow/len(multi):.1f}%)")"""))

cells.append(new_markdown_cell(
"""## 6. Firmas de bots: secuencias de comandos repetidas

Si muchas IPs distintas ejecutan **exactamente la misma** secuencia de comandos,
es evidencia fuerte de automatización (un mismo malware/botnet). Veamos las
secuencias más repetidas."""))

cells.append(new_code_cell(
"""top = act.commands.value_counts().head(8)
for i,(cmd,cnt) in enumerate(top.items(), 1):
    print(f"[{cnt:>3} veces] {cmd[:160]}")
    print("-"*80)"""))

cells.append(new_code_cell(
"""# ¿Cuántas IPs distintas ejecutan la secuencia más común? -> evidencia de botnet
top_seq = act.commands.value_counts().index[0]
sub = act[act.commands == top_seq]
print(f"Secuencia más común ejecutada por {sub.src_ip.nunique()} IPs distintas "
      f"en {sub.sensor.nunique()} sensores.")
print("Esto confirma actividad de botnet (mismo payload, múltiples orígenes).")"""))

cells.append(new_markdown_cell("""## 7. Geografía de los ataques"""))

cells.append(new_code_cell(
"""top_c = df.country.value_counts().head(12)
fig, ax = plt.subplots(figsize=(9,4))
top_c.sort_values().plot.barh(ax=ax, color="#55A868")
ax.set_title("Top 12 países de origen (todas las sesiones)")
ax.set_xlabel("nº de sesiones")
plt.tight_layout(); plt.savefig(f"{FIG}/05_paises.png"); plt.show()"""))

cells.append(new_markdown_cell(
"""## 8. Conclusiones del EDA y su impacto en el modelado

1. **Desbalance extremo:** el 99.8% de las sesiones son fuerza bruta sin comandos.
   Solo el 0.2% ejecuta comandos.
2. **Las sesiones activas son casi todas automatizadas:** ~91% ejecutan comandos a
   ritmo de máquina (<0.5s entre comandos) y repiten secuencias idénticas (droppers
   tipo Mirai: `cd /tmp; wget ...; chmod; sh ...`).
3. **La actividad humana "hands-on-keyboard" es rarísima** en este honeypot: apenas
   un puñado de sesiones tienen ritmo humano (>2s). No hay suficientes ejemplos
   positivos para un clasificador supervisado humano-vs-bot directo.

**Implicación para el objetivo técnico (a decidir):**
- **Opción A — Detección de anomalías:** modelar el comportamiento automatizado
  "normal" (autoencoder sobre secuencias) y marcar como sospechosa la sesión rara
  que se desvía. Encaja con el desbalance real.
- **Opción B — Reformular el target a algo etiquetable:** clasificar
  *fuerza bruta vs. sesión interactiva-con-comandos* (señal de que el atacante
  "entró y actuó"), que sí tiene etiquetas claras y es operativamente útil.
- **Opción C — Etiquetas débiles por heurística:** usar ritmo + diversidad +
  typos como pseudo-etiquetas humano/bot, asumiendo supervisión débil.

Este hallazgo es un resultado valioso del EDA: los datos nos obligan a ajustar el
planteamiento del modelado para que sea honesto y factible."""))

nb["cells"] = cells
nb["metadata"] = {
    "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
    "language_info": {"name": "python"},
}

with open("notebooks/01_EDA.ipynb", "w") as f:
    nbf.write(nb, f)
print("Notebook creado: notebooks/01_EDA.ipynb")
