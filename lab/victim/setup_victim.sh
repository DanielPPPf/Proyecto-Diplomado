#!/usr/bin/env bash
#
# Configura la VM VÍCTIMA: honeypot Cowrie + servicio de inferencia + agente Wazuh.
#
# Diseño seguro: Cowrie escucha en 2222 (los ataques se dirigen ahí) y el sshd de
# administración se queda en el 22 (no nos quedamos fuera de la VM).
#
# Probado contra Ubuntu 22.04 + Wazuh manager 4.13.1. Ajusta las variables.
#
# Uso (como root):
#   WAZUH_MANAGER=<IP_PRIVADA_DEL_MANAGER> WAZUH_VERSION=4.13.1 bash setup_victim.sh
#
# Notas aprendidas en el despliegue real:
#  - El Cowrie actual (master) se instala con `pip install -e .` (ya no hay
#    bin/cowrie ni etc/cowrie.cfg.dist); se arranca con el console script `cowrie`.
#  - El systemd de Cowrie necesita el venv en el PATH (cowrie hace execvp de twistd).
#  - Los modelos se guardaron con Keras 2 -> fijar tensorflow-cpu==2.14.0.
#  - El agente Wazuh debe ser de versión <= manager -> fijar WAZUH_VERSION = manager.
#  - Usa la IP PRIVADA del manager (regla del SG es por source-group).
#
set -euo pipefail
WAZUH_MANAGER="${WAZUH_MANAGER:?Define WAZUH_MANAGER=<IP privada del manager>}"
WAZUH_VERSION="${WAZUH_VERSION:-4.13.1}"
APP_DIR=/opt/ssh-classifier
VERDICT_DIR=/var/log/ssh-classifier
COWRIE_JSON=/home/cowrie/cowrie/var/log/cowrie/cowrie.json

echo "==> [1/6] Paquetes base"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y git python3 python3-venv python3-pip python3-dev \
                   libssl-dev libffi-dev build-essential curl gnupg lsb-release

echo "==> [2/6] Honeypot Cowrie (usuario cowrie, puerto 2222)"
id cowrie &>/dev/null || adduser --disabled-password --gecos "" cowrie
sudo -u cowrie bash <<'COWRIE'
set -e
cd ~
[ -d cowrie ] || git clone https://github.com/cowrie/cowrie.git
cd cowrie
python3 -m venv cowrie-env
. cowrie-env/bin/activate
pip install --upgrade pip wheel setuptools
pip install -e .                       # instala el paquete + console script 'cowrie'
mkdir -p var/log/cowrie var/run
cat > etc/cowrie.cfg <<'CFG'
[honeypot]
hostname = svr04
log_path = var/log/cowrie

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = false

[output_jsonlog]
enabled = true
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = false
CFG
cat > etc/userdb.txt <<'UDB'
root:x:lab123
root:x:!root
root:x:*
UDB
deactivate
COWRIE

echo "==> [3/6] Servicio systemd de Cowrie (con venv en PATH)"
cat >/etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target
[Service]
Type=forking
User=cowrie
WorkingDirectory=/home/cowrie/cowrie
Environment=HOME=/home/cowrie
Environment=PATH=/home/cowrie/cowrie/cowrie-env/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start
ExecStop=/home/cowrie/cowrie/cowrie-env/bin/cowrie stop
PIDFile=/home/cowrie/cowrie/var/run/cowrie.pid
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

echo "==> [4/6] Servicio de inferencia (TensorFlow 2.14 = formato de los modelos)"
mkdir -p "$APP_DIR" "$VERDICT_DIR"; touch "$VERDICT_DIR/verdicts.json"
# Se asume que ya copiaste a $APP_DIR (vía scp): infer_service.py y models/
python3 -m venv "$APP_DIR/venv"
. "$APP_DIR/venv/bin/activate"
pip install --upgrade pip
pip install "numpy<2.0" "tensorflow-cpu==2.14.0"
deactivate

cat >/etc/systemd/system/ssh-classifier.service <<EOF
[Unit]
Description=Clasificador SSH (inferencia en vivo sobre Cowrie)
After=cowrie.service
[Service]
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/infer_service.py \\
          --follow $COWRIE_JSON --out $VERDICT_DIR/verdicts.json --models $APP_DIR/models
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

echo "==> [5/6] Agente Wazuh v$WAZUH_VERSION (manager=$WAZUH_MANAGER)"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
     --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
     >/etc/apt/sources.list.d/wazuh.list
apt-get update -y
# versión EXACTA del manager para evitar 'agent version must be <= manager'
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y "wazuh-agent=${WAZUH_VERSION}-1"
apt-mark hold wazuh-agent

# añadir los localfile (veredictos + cowrie) antes de </ossec_config>
if ! grep -q ssh-classifier /var/ossec/etc/ossec.conf; then
  sed -i "s#</ossec_config>#  <localfile>\n    <log_format>json</log_format>\n    <location>$VERDICT_DIR/verdicts.json</location>\n  </localfile>\n  <localfile>\n    <log_format>json</log_format>\n    <location>$COWRIE_JSON</location>\n  </localfile>\n</ossec_config>#" \
      /var/ossec/etc/ossec.conf
fi

echo "==> [6/6] Arrancando servicios"
systemctl daemon-reload
systemctl enable --now cowrie.service
systemctl enable --now ssh-classifier.service
systemctl enable --now wazuh-agent

echo ""
echo "LISTO. Cowrie escucha en :2222, veredictos en $VERDICT_DIR/verdicts.json"
echo "Verifica:  systemctl status cowrie ssh-classifier wazuh-agent"
echo "En el manager:  /var/ossec/bin/agent_control -l   (la víctima debe salir Active)"
