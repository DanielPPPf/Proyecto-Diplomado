"""
Parsing del dataset CyberLab (honeypot Cowrie) a nivel de sesión.

El formato crudo es un array JSON donde cada elemento es un dict
{session_id: [lista de eventos]}. Cada evento tiene 'eventid', 'timestamp',
'message' (los comandos vienen como "CMD: <cmd>") y metadatos.

Este módulo agrega cada sesión en una sola fila con features de
comportamiento orientadas a distinguir actividad automatizada vs. humana.
"""

import gzip
import json
import glob
import os
from datetime import datetime

import numpy as np
import pandas as pd


def _parse_ts(ts):
    """Convierte un timestamp ISO de Cowrie a datetime (UTC, naive)."""
    if not ts:
        return None
    # formato: 2019-08-24T00:07:55.644068Z
    return datetime.strptime(ts[:26].ljust(26, "0"), "%Y-%m-%dT%H:%M:%S.%f")


def iter_sessions(path):
    """Itera (session_id, eventos) sobre un archivo .json.gz de un día."""
    with gzip.open(path, "rt") as f:
        data = json.load(f)
    for entry in data:
        for sid, events in entry.items():
            yield sid, events


def session_features(sid, events):
    """Extrae una fila de features a partir de los eventos de una sesión."""
    commands = []          # texto de cada comando
    cmd_times = []         # timestamp de cada comando
    connect_t = close_t = None
    duration = None
    n_login_ok = n_login_fail = 0
    n_downloads = 0
    country = None
    src_ip = None
    sensor = None
    client_version = None

    for e in events:
        eid = e.get("eventid")
        ts = _parse_ts(e.get("timestamp"))

        if eid == "cowrie.session.connect":
            connect_t = ts
            src_ip = e.get("src_ip_identifier")
            sensor = e.get("sensor")
        elif eid == "cowrie.session.closed":
            close_t = ts
            if e.get("duration") is not None:
                duration = float(e["duration"])
        elif eid == "cowrie.login.success":
            n_login_ok += 1
        elif eid == "cowrie.login.failed":
            n_login_fail += 1
        elif eid == "cowrie.command.input":
            msg = e.get("message", "") or ""
            cmd = msg[5:] if msg.startswith("CMD: ") else msg
            commands.append(cmd)
            if ts:
                cmd_times.append(ts)
        elif eid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
            n_downloads += 1
        elif eid == "cowrie.client.version":
            msg = e.get("message", "") or ""
            client_version = msg

        geo = e.get("geolocation_data") or {}
        if country is None and geo.get("country_name"):
            country = geo["country_name"]

    # duración: usa la del evento si existe, si no la calcula
    if duration is None and connect_t and close_t:
        duration = (close_t - connect_t).total_seconds()

    # estadísticos de ritmo entre comandos (gaps en segundos)
    gaps = []
    if len(cmd_times) >= 2:
        cmd_times_sorted = sorted(cmd_times)
        gaps = [
            (cmd_times_sorted[i + 1] - cmd_times_sorted[i]).total_seconds()
            for i in range(len(cmd_times_sorted) - 1)
        ]
    gaps = np.array(gaps) if gaps else np.array([])

    n_cmd = len(commands)
    uniq_cmd = len(set(commands))
    total_cmd_len = sum(len(c) for c in commands)

    return {
        "session_id": sid,
        "src_ip": src_ip,
        "sensor": sensor,
        "country": country,
        "client_version": client_version,
        "connect_time": connect_t,
        "duration": duration,
        "n_login_ok": n_login_ok,
        "n_login_fail": n_login_fail,
        "n_login_total": n_login_ok + n_login_fail,
        "n_commands": n_cmd,
        "n_unique_commands": uniq_cmd,
        "cmd_diversity": (uniq_cmd / n_cmd) if n_cmd else 0.0,
        "n_downloads": n_downloads,
        "total_cmd_chars": total_cmd_len,
        "avg_cmd_len": (total_cmd_len / n_cmd) if n_cmd else 0.0,
        "gap_mean": float(gaps.mean()) if gaps.size else np.nan,
        "gap_std": float(gaps.std()) if gaps.size else np.nan,
        "gap_min": float(gaps.min()) if gaps.size else np.nan,
        "gap_max": float(gaps.max()) if gaps.size else np.nan,
        # secuencia de comandos unida con separador, para modelado posterior
        "commands": " || ".join(commands),
    }


def build_dataframe(paths):
    """Construye un DataFrame (una fila por sesión) a partir de varios días."""
    rows = []
    for p in paths:
        day = os.path.basename(p)
        for sid, events in iter_sessions(p):
            row = session_features(sid, events)
            row["source_file"] = day
            rows.append(row)
    return pd.DataFrame(rows)


if __name__ == "__main__":
    raw_dir = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
    out_dir = os.path.join(os.path.dirname(__file__), "..", "data", "processed")
    os.makedirs(out_dir, exist_ok=True)

    paths = sorted(glob.glob(os.path.join(raw_dir, "cyberlab_*.json.gz")))
    print(f"Procesando {len(paths)} archivos...")
    df = build_dataframe(paths)
    print(f"Sesiones totales: {len(df):,}")

    out = os.path.join(out_dir, "sessions.parquet")
    df.to_parquet(out, index=False)
    print(f"Guardado: {out}")
