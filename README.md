# Detección de atacantes humanos vs. ataques automatizados en sesiones SSH

Proyecto final del Diplomado de Deep Learning.

Modelo de deep learning que clasifica sesiones SSH capturadas por un honeypot
(Cowrie) en **automatizadas** (bots, escáneres, gusanos) vs. **interactivas
humanas** ("hands-on-keyboard"), a partir de la secuencia temporal de comandos.

---

## 1. Objetivos

### Objetivo de negocio
Las organizaciones reciben miles de intentos de acceso SSH no autorizados al día,
la inmensa mayoría automatizados (botnets, escáneres, gusanos como Mirai) y de bajo
riesgo. Una fracción pequeña corresponde a un **atacante humano interactuando en
vivo**, que indica un ataque dirigido, de mayor severidad y que exige respuesta
inmediata. El objetivo es **priorizar la respuesta a incidentes**: ayudar al SOC a
separar el ruido automatizado de las intrusiones humanas activas para concentrar
recursos donde el riesgo real es mayor, reduciendo el tiempo de detección de
amenazas dirigidas.

### Objetivo técnico
El EDA mostró que el 99.8% de las sesiones son fuerza bruta sin comandos y que las
sesiones activas son casi todas automatizadas (ritmo de máquina, payloads Mirai
repetidos), con muy pocas candidatas a actividad humana. Por ello el objetivo se
formula como un **enfoque combinado** de dos modelos de deep learning:

1. **Clasificador de escalada (supervisado).** Predecir si una sesión será
   *fuerza bruta* vs. *interactiva* (ejecuta comandos) a partir de señales de la
   fase de login (intentos, duración, país, versión del cliente), sin usar los
   comandos como entrada. MLP de Keras con manejo de desbalance extremo, evaluado
   con precision, recall, F1, AUC y PR-curve.
2. **Detección de anomalías (no supervisado).** Autoencoder sobre la secuencia de
   comandos de las sesiones activas, que aprende el payload automatizado "normal"
   y marca por error de reconstrucción las sesiones raras —candidatas a actividad
   humana o novedosa— rescatando la intención original del proyecto.

---

## 2. Estructura del proyecto

```
.
├── data/
│   ├── raw/          # Datasets originales (no versionados)
│   └── processed/    # Datos parseados / features (no versionados)
├── notebooks/        # EDA, experimentos, entrenamiento
├── src/              # Código reutilizable (parsing, features, modelo)
├── models/           # Pesos entrenados (no versionados)
├── reports/
│   └── figures/      # Gráficas para el reporte final
└── README.md
```

## 3. Datos

- **CyberLab honeynet dataset** (Zenodo): https://zenodo.org/records/3687527 —
  Cowrie en ~50 nodos (EU/US), mayo 2019 – feb 2020, IPs pseudonimizadas.
- **Medium-interaction SSH honeypot data** (Kaggle):
  https://www.kaggle.com/datasets/xmlyna/cowrie-honeypot

## 4. Referencias

- *Towards Identifying Human Actions, Intent, and Severity of APT Attacks Applying
  Deception Techniques* — https://arxiv.org/pdf/2006.01849
- *GPT-2C: A GPT-2 parser for Cowrie honeypot logs* — https://arxiv.org/pdf/2109.06595

## 5. Etapas

- [x] 1. Definición de objetivos (negocio y técnico)
- [x] 2. Análisis Exploratorio de Datos (EDA) — `notebooks/01_EDA.ipynb`
- [x] 3. Modelamiento — Modelo 1 (`02_...`) + Modelo 2 (`03_...`)
- [x] 4. Evaluación — métricas M1 (PR-AUC, validación temporal) + anomalías M2
- [ ] 5. Reporte final
