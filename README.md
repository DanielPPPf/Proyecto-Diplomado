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
Desarrollar un modelo de deep learning que clasifique sesiones SSH (Cowrie) en
**automatizada vs. interactiva-humana**, a partir de la secuencia temporal de
comandos y sus metadatos (intervalos entre comandos, duración de sesión, longitud
y tipo de comandos, presencia de errores/typos). La sesión se modela como una
**secuencia** mediante una arquitectura recurrente (LSTM/GRU) o convolucional 1D,
evaluada con métricas para clases desbalanceadas (precision, recall, F1, AUC).
Diseñado para inferencia por sesión, como base de una detección en tiempo casi real.

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
- [ ] 2. Análisis Exploratorio de Datos (EDA)
- [ ] 3. Modelamiento (diseño experimental, modelo, datos, entrenamiento)
- [ ] 4. Evaluación
- [ ] 5. Reporte final
