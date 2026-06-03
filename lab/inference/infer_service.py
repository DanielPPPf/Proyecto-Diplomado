#!/usr/bin/env python3
"""
Servicio de inferencia del laboratorio: clasifica sesiones SSH de un honeypot
Cowrie EN VIVO como AUTOMATIZADO vs MANUAL, y escribe el veredicto en un log
JSON que el agente de Wazuh recoge para alertar en el dashboard.

Reusa los modelos entrenados en el proyecto:
  - Modelo 2 (autoencoder de secuencias)  -> error de reconstrucción (contenido anómalo)
  - Heurística de ritmo (gap entre comandos) -> pausas humanas
  - Modelo 1 (clasificador)                -> riesgo de escalada (enriquecimiento)

El veredicto se centra en ritmo + anomalía, las dos señales validadas en el
reporte. Parsea el formato CRUDO de Cowrie (cowrie.json, una línea = un evento).

Uso:
  # procesar un archivo estático (pruebas)
  python3 infer_service.py --replay /ruta/cowrie.json --out verdicts.json
  # seguir el log en vivo
  python3 infer_service.py --follow /var/log/cowrie/cowrie.json --out /var/log/cowrie/verdicts.json
"""
import argparse
import json
import math
import os
import time
from collections import defaultdict
from datetime import datetime

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
MODELS = os.path.join(ROOT, "models")

RHYTHM_HUMAN_S = 2.0          # gap medio > 2s => ritmo humano
IDLE_FLUSH_S = 30.0           # cerrar sesión por inactividad si no llega session.closed


# ----------------------------- carga de artefactos -----------------------------
def load_artifacts(models_dir):
    import tensorflow as tf
    from tensorflow import keras

    with open(os.path.join(models_dir, "inference_artifacts", "m2_vocab.json")) as f:
        m2 = json.load(f)
    with open(os.path.join(models_dir, "inference_artifacts", "m1_preprocess.json")) as f:
        m1 = json.load(f)
    ae = keras.models.load_model(os.path.join(models_dir, "modelo2_autoencoder.keras"),
                                 compile=False)
    clf = keras.models.load_model(os.path.join(models_dir, "modelo1_clasificador.keras"),
                                  compile=False)
    return {"m2": m2, "m1": m1, "ae": ae, "clf": clf, "tf": tf}


# ----------------------------- parsing de eventos -----------------------------
def parse_ts(ts):
    if not ts:
        return None
    try:
        return datetime.strptime(ts[:26].ljust(26, "0"), "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        return None


def event_session_id(e):
    return e.get("session") or e.get("session_id")


def event_command(e):
    """Texto del comando en formato crudo (campo 'input') o CyberLab ('CMD: ...')."""
    if e.get("input"):
        return e["input"]
    msg = e.get("message", "") or ""
    return msg[5:] if msg.startswith("CMD: ") else ""


# ----------------------------- features por sesión -----------------------------
class Session:
    __slots__ = ("sid", "connect_t", "close_t", "duration", "n_ok", "n_fail",
                 "commands", "cmd_times", "client_version", "sensor", "src_ip", "last_t")

    def __init__(self, sid):
        self.sid = sid
        self.connect_t = self.close_t = self.duration = None
        self.n_ok = self.n_fail = 0
        self.commands = []
        self.cmd_times = []
        self.client_version = None
        self.sensor = None
        self.src_ip = None
        self.last_t = None

    def add(self, e):
        eid = e.get("eventid")
        ts = parse_ts(e.get("timestamp"))
        if ts:
            self.last_t = ts
        if eid == "cowrie.session.connect":
            self.connect_t = ts
            self.src_ip = e.get("src_ip") or e.get("src_ip_identifier")
            self.sensor = e.get("sensor")
        elif eid == "cowrie.client.version":
            v = e.get("version")
            if v:
                self.client_version = f"Remote SSH version: b'{v}'"
            elif e.get("message"):
                self.client_version = e["message"]
        elif eid == "cowrie.login.success":
            self.n_ok += 1
        elif eid == "cowrie.login.failed":
            self.n_fail += 1
        elif eid in ("cowrie.command.input", "cowrie.command.failed"):
            cmd = event_command(e)
            self.commands.append(cmd)
            if ts:
                self.cmd_times.append(ts)
        elif eid == "cowrie.session.closed":
            self.close_t = ts
            if e.get("duration") is not None:
                self.duration = float(e["duration"])

    def features(self):
        if self.duration is None and self.connect_t and self.last_t:
            self.duration = (self.last_t - self.connect_t).total_seconds()
        gaps = []
        if len(self.cmd_times) >= 2:
            t = sorted(self.cmd_times)
            gaps = [(t[i + 1] - t[i]).total_seconds() for i in range(len(t) - 1)]
        gaps = np.array(gaps) if gaps else np.array([])
        return {
            "session": self.sid,
            "src_ip": self.src_ip,
            "duration": float(self.duration or 0.0),
            "n_login_ok": self.n_ok,
            "n_login_fail": self.n_fail,
            "n_login_total": self.n_ok + self.n_fail,
            "n_commands": len(self.commands),
            "gap_mean": float(gaps.mean()) if gaps.size else None,
            "client_version": self.client_version,
            "sensor": self.sensor,
            "commands": " || ".join(self.commands),
        }


# ----------------------------- inferencia -----------------------------
def m2_recon_error(art, command_str):
    """Error medio de reconstrucción del autoencoder para una cadena de comandos."""
    m2 = art["m2"]
    stoi, L = m2["stoi"], m2["L"]
    ids = [stoi.get(ch, 0) for ch in command_str[:L]]
    ids = ids + [0] * (L - len(ids))
    X = np.array([ids], dtype=np.int32)
    probs = art["ae"].predict(X, verbose=0)[0]            # (L, vocab)
    true_p = probs[np.arange(L), X[0]]
    mask = (X[0] != 0)
    if mask.sum() == 0:
        return 0.0
    ce = -np.log(true_p + 1e-9)
    return float((ce * mask).sum() / mask.sum())


def m1_escalation_prob(art, feat):
    """Probabilidad de escalada del Modelo 1 a partir de features de login."""
    m1 = art["m1"]
    num = np.log1p(np.clip([feat[c] for c in m1["num_cols"]], 0, None))
    row = {c: 0.0 for c in m1["dummy_cols"]}

    def setcat(prefix, value, top):
        v = value if (value in top) else "OTHER"
        if value is None:
            v = "NA" if "NA" in top else "OTHER"
        col = f"{prefix}_{v}"
        if col in row:
            row[col] = 1.0

    setcat("sensor", feat["sensor"], m1["sensor_top"])
    setcat("country", None, m1["country_top"])  # país no disponible en vivo -> OTHER/NA
    setcat("client_version", feat["client_version"], m1["client_top"])

    x = np.concatenate([num, np.array([row[c] for c in m1["dummy_cols"]])])
    x = (x - np.array(m1["scaler_mean"])) / np.array(m1["scaler_std"])
    return float(art["clf"].predict(x[None, :].astype(np.float32), verbose=0).ravel()[0])


def classify(art, feat):
    """
    Veredicto en dos ejes (separados a propósito):
      - AUTOMATED vs MANUAL  -> lo decide el RITMO (pausas humanas).
      - novel_campaign        -> lo decide el Modelo 2 (contenido inusual);
                                 NO implica 'manual' (un bot nuevo también es raro).
    Con <2 comandos no hay ritmo fiable -> UNCERTAIN.
    """
    m2 = art["m2"]
    t_review = m2.get("threshold_review", m2["threshold"])
    t_novel = m2.get("threshold_novel", m2["threshold"])

    recon = m2_recon_error(art, feat["commands"]) if feat["n_commands"] > 0 else 0.0
    gap = feat["gap_mean"]
    rhythm_human = (gap is not None and gap > RHYTHM_HUMAN_S)
    novel_campaign = recon > t_novel
    needs_review = rhythm_human or recon > t_review
    escalation = m1_escalation_prob(art, feat)

    # eje principal: ritmo
    if gap is None:                       # <2 comandos: sin señal de ritmo
        verdict = "UNCERTAIN"
        reason = "comando único; sin ritmo para decidir auto/manual"
    elif rhythm_human:
        verdict = "MANUAL"
        reason = f"ritmo humano (gap_mean={gap:.2f}s > {RHYTHM_HUMAN_S}s)"
    else:
        verdict = "AUTOMATED"
        reason = f"ritmo de máquina (gap_mean={gap:.2f}s)"

    if novel_campaign:
        reason += f"; campaña NOVEDOSA (recon_err={recon:.2f} > {t_novel:.2f})"
    elif recon > t_review:
        reason += f"; contenido inusual (recon_err={recon:.2f} > {t_review:.2f})"

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "session": feat["session"],
        "src_ip": feat["src_ip"],
        "n_commands": feat["n_commands"],
        "gap_mean": round(gap, 3) if gap is not None else None,
        "recon_err": round(recon, 3),
        "novel_campaign": bool(novel_campaign),
        "rhythm_human": bool(rhythm_human),
        "needs_review": bool(needs_review),
        "escalation_prob": round(escalation, 3),
        "verdict": verdict,
        "reason": reason,
    }


def emit(out_fh, verdict):
    out_fh.write(json.dumps(verdict) + "\n")
    out_fh.flush()
    print(f"[{verdict['verdict']:9s}] sid={verdict['session']} "
          f"cmds={verdict['n_commands']} gap={verdict['gap_mean']} "
          f"recon={verdict['recon_err']} :: {verdict['reason']}")


# ----------------------------- modos -----------------------------
def iter_events(lines):
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def run_replay(art, infile, outfile, only_with_commands=True):
    sessions = defaultdict(lambda: None)
    order = []
    with open(infile) as f:
        for e in iter_events(f):
            sid = event_session_id(e)
            if not sid:
                continue
            if sessions[sid] is None:
                sessions[sid] = Session(sid)
                order.append(sid)
            sessions[sid].add(e)

    n = 0
    with open(outfile, "w") as out:
        for sid in order:
            feat = sessions[sid].features()
            if only_with_commands and feat["n_commands"] == 0:
                continue
            emit(out, classify(art, feat))
            n += 1
    print(f"\nProcesadas {n} sesiones con comandos. Veredictos en {outfile}")


def run_follow(art, infile, outfile):
    sessions = {}
    print(f"Siguiendo {infile} ... (Ctrl-C para salir)")
    with open(outfile, "a") as out, open(infile) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                # flush de sesiones inactivas
                now = datetime.utcnow()
                for sid in list(sessions):
                    s = sessions[sid]
                    if s.last_t and (now - s.last_t).total_seconds() > IDLE_FLUSH_S:
                        feat = s.features()
                        if feat["n_commands"] > 0:
                            emit(out, classify(art, feat))
                        del sessions[sid]
                time.sleep(0.5)
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = event_session_id(e)
            if not sid:
                continue
            if sid not in sessions:
                sessions[sid] = Session(sid)
            sessions[sid].add(e)
            if e.get("eventid") == "cowrie.session.closed":
                feat = sessions[sid].features()
                if feat["n_commands"] > 0:
                    emit(out, classify(art, feat))
                del sessions[sid]


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--replay", help="archivo cowrie.json a procesar una vez")
    g.add_argument("--follow", help="archivo cowrie.json a seguir en vivo")
    ap.add_argument("--out", default="verdicts.json", help="log de veredictos")
    ap.add_argument("--models", default=MODELS, help="directorio de modelos")
    args = ap.parse_args()

    print("Cargando modelos y artefactos...")
    art = load_artifacts(args.models)
    print(f"Umbral de anomalía (M2): {art['m2']['threshold']:.3f}\n")

    if args.replay:
        run_replay(art, args.replay, args.out)
    else:
        run_follow(art, args.follow, args.out)


if __name__ == "__main__":
    main()
