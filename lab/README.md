# Laboratorio en vivo: clasificación de ataques SSH (AUTOMATED vs MANUAL)

Demuestra que los modelos del proyecto **se usan en operación**, no solo se
entrenan. Atacas un honeypot, el servicio de inferencia clasifica cada sesión en
tiempo real y Wazuh muestra alertas **AUTOMATIZADO / MANUAL** en su dashboard.

## Arquitectura

```
[Atacante (tú)] --SSH:2222--> [VICTIM: Cowrie + infer_service + agente Wazuh]
   auto_attack.sh                     |  cowrie.json (eventos por comando)
   manual_playbook.md                 v
                            infer_service.py  (Modelo 2 + ritmo + Modelo 1)
                                       |  verdicts.json
                                       v  (agente Wazuh, log_format json)
                              [MANAGER: Wazuh all-in-one]
                                       |  reglas 1001xx
                                       v
                          [Dashboard: alertas AUTO / MANUAL]
```

## Componentes

| Archivo | Rol |
|---|---|
| `aws/provision.sh` / `aws/teardown.sh` | Crear / destruir el lab en AWS |
| `victim/setup_victim.sh` | Instala Cowrie + inferencia + agente en la víctima |
| `inference/infer_service.py` | Servicio que clasifica sesiones (modos `--replay`/`--follow`) |
| `wazuh/cowrie_verdict_rules.xml` | Reglas de alerta AUTO/MANUAL/novedoso |
| `wazuh/agent_ossec.conf.snippet` | Bloques `localfile` para el agente |
| `attacks/auto_attack.sh` | Ataques automatizados (hydra + dropper) |
| `attacks/manual_playbook.md` | Guion del ataque manual (humano) |

## Prueba local (sin AWS, gratis)

Valida el pipeline antes de desplegar:

```bash
conda activate diplomadoDL
python3 inference/infer_service.py --replay inference/sample_cowrie.json --out /tmp/v.json
```

Debe clasificar la sesión Mirai como AUTOMATED y la lenta como MANUAL.

## Despliegue en AWS

```bash
cd lab/aws
REGION=us-east-1 bash provision.sh        # crea manager + victim
```

1. **Espera ~10 min** a que Wazuh termine de instalarse en el manager
   (`ssh ubuntu@<manager>` → `sudo tail -f /var/log/wazuh-install.log`).
   La contraseña de `admin` sale de `wazuh-install-files.tar` en el manager.

2. **Copia modelos + servicio a la víctima** y ejecútale el setup:
   ```bash
   scp -i ~/.ssh/ssh-classifier-lab-key.pem inference/infer_service.py \
       -r ../models ubuntu@<victim>:/tmp/
   ssh -i ~/.ssh/ssh-classifier-lab-key.pem ubuntu@<victim>
   sudo mkdir -p /opt/ssh-classifier && sudo mv /tmp/infer_service.py /tmp/models /opt/ssh-classifier/
   # sube también setup_victim.sh y córrelo:
   sudo WAZUH_MANAGER=<manager_ip> bash setup_victim.sh
   ```

3. **Instala las reglas en el manager:**
   ```bash
   scp -i ...pem wazuh/cowrie_verdict_rules.xml ubuntu@<manager>:/tmp/
   ssh ... ubuntu@<manager>
   sudo cp /tmp/cowrie_verdict_rules.xml /var/ossec/etc/rules/local_rules.xml
   sudo systemctl restart wazuh-manager
   ```

4. **Verifica el agente** en el dashboard (Management → Agents): la víctima debe
   aparecer *Active*.

## Ejecutar el experimento

```bash
# ataques automatizados
bash attacks/auto_attack.sh <victim_ip>
# ataque manual: sigue attacks/manual_playbook.md (teclea con pausas)
```

Observa en la víctima:
```bash
ssh ... ubuntu@<victim> 'tail -f /var/log/ssh-classifier/verdicts.json'
```

## Visualización en el dashboard

1. Dashboard Wazuh → **Threat Hunting** / Discover.
2. Filtro: `data.app: "ssh-classifier"`.
3. Crea una **visualización tipo pastel** agrupada por `data.verdict`
   (AUTOMATED vs MANUAL) y una **tabla** con `data.src_ip`, `data.verdict`,
   `data.reason`, `data.recon_err`.
4. Guárdalas en un **dashboard** llamado *"SSH Auto vs Manual"*.
   Las alertas MANUAL son nivel 12 → resaltan en Security Alerts.

## Costo y limpieza ⚠️

- `t3.large` (~US$0.083/h) + `t3.medium` (~US$0.042/h) ≈ **US$0.13/h ≈ US$3/día**.
- **Al terminar, destruye todo** para no seguir pagando:
  ```bash
  cd lab/aws && REGION=us-east-1 bash teardown.sh
  ```

## Limitaciones honestas (para el reporte)

- El veredicto AUTO/MANUAL se basa en el **ritmo**: un atacante humano que pegue
  comandos de golpe se vería como automatizado (lo mitiga parcialmente el Modelo 2).
- Cowrie es un honeypot de interacción media; un atacante avanzado podría
  detectarlo. Para el lab es suficiente y reproduce el esquema de entrenamiento.
- El honeypot en `:2222` abierto a internet recibirá ataques reales: útil para el
  demo, pero recuerda destruir el lab al terminar.
