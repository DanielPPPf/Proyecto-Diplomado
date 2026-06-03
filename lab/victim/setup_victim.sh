#!/usr/bin/env bash
#
# Configura la VM VÍCTIMA: honeypot Cowrie + servicio de inferencia + agente Wazuh.
#
# Diseño seguro: Cowrie escucha en el puerto 2222 (los ataques se dirigen ahí),
# y el sshd de administración se queda en el 22 (no nos quedamos fuera de la VM).
#
# Uso (como root en Ubuntu 22.04):
#   WAZUH_MANAGER=<IP_DEL_MANAGER> bash setup_victim.sh
#
set -euo pipefail
WAZUH_MANAGER="${WAZUH_MANAGER:?Define WAZUH_MANAGER=<IP del manager>}"
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
pip install --upgrade pip wheel
pip install -r requirements.txt
[ -f etc/cowrie.cfg ] || cp etc/cowrie.cfg.dist etc/cowrie.cfg
[ -f etc/userdb.txt ] || cp etc/userdb.example etc/userdb.txt
# credencial garantizada para el laboratorio (root/lab123)
grep -q '^root:x:lab123' etc/userdb.txt || echo 'root:x:lab123' >> etc/userdb.txt
# salida JSON activada (por defecto), escucha en 2222
deactivate
COWRIE

echo "==> [3/6] Servicio systemd de Cowrie"
cat >/etc/systemd/system/cowrie.service <<EOF
[Unit]
Description=Cowrie SSH Honeypot
After=network.target
[Service]
Type=forking
User=cowrie
ExecStart=/home/cowrie/cowrie/bin/cowrie start
ExecStop=/home/cowrie/cowrie/bin/cowrie stop
PIDFile=/home/cowrie/cowrie/var/run/cowrie.pid
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF

echo "==> [4/6] Servicio de inferencia (modelos del proyecto)"
mkdir -p "$APP_DIR" "$VERDICT_DIR"
# Se asume que ya copiaste a $APP_DIR (vía scp):
#   infer_service.py, models/modelo1_clasificador.keras,
#   models/modelo2_autoencoder.keras, models/inference_artifacts/*
python3 -m venv "$APP_DIR/venv"
. "$APP_DIR/venv/bin/activate"
pip install --upgrade pip
pip install "numpy<2.0" tensorflow-cpu
deactivate

cat >/etc/systemd/system/ssh-classifier.service <<EOF
[Unit]
Description=Clasificador SSH (inferencia en vivo sobre Cowrie)
After=cowrie.service
[Service]
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/infer_service.py \\
          --follow $COWRIE_JSON \\
          --out $VERDICT_DIR/verdicts.json \\
          --models $APP_DIR/models
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF

echo "==> [5/6] Agente Wazuh (manager=$WAZUH_MANAGER)"
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
     --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
     >/etc/apt/sources.list.d/wazuh.list
apt-get update -y
WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y wazuh-agent

# añadir los localfile (veredictos + cowrie) antes de </ossec_config>
if ! grep -q ssh-classifier /var/ossec/etc/ossec.conf; then
  sed -i "s#</ossec_config>#  <localfile>\n    <log_format>json</log_format>\n    <location>$VERDICT_DIR/verdicts.json</location>\n  </localfile>\n  <localfile>\n    <log_format>json</log_format>\n    <location>$COWRIE_JSON</location>\n  </localfile>\n</ossec_config>#" \
      /var/ossec/etc/ossec.conf
fi

echo "==> [6/6] Arrancando servicios"
touch "$VERDICT_DIR/verdicts.json"
systemctl daemon-reload
systemctl enable --now cowrie.service
systemctl enable --now ssh-classifier.service
systemctl enable --now wazuh-agent

echo ""
echo "LISTO. Cowrie escucha en :2222, veredictos en $VERDICT_DIR/verdicts.json"
echo "Verifica:  systemctl status cowrie ssh-classifier wazuh-agent"
