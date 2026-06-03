# Playbook de ataque MANUAL (humano hands-on-keyboard)

El objetivo es generar una sesión que el clasificador etiquete como **MANUAL**:
comandos tecleados **con pausas humanas** (varios segundos entre uno y otro) y
exploración no estándar.

## Cómo

Conéctate al honeypot e interactúa **tú mismo**, sin pegar todo de golpe. Teclea
cada comando, lee la salida, piensa, y luego escribe el siguiente (deja pasar
3–10 s entre comandos — eso es lo que detecta la heurística de ritmo).

```bash
ssh -p 2222 root@<IP_VICTIMA>
# contraseña: lab123
```

Sugerencia de comandos de reconocimiento (escríbelos despacio, uno a uno):

```
whoami
id
uname -a
ls -la /root
cat /etc/passwd
ps aux | grep -i ssh
netstat -tulpn
cat /etc/shadow
find / -perm -4000 -type f 2>/dev/null
crontab -l
```

Sal con `exit`. Al cerrarse la sesión, el servicio emite el veredicto.

## Qué esperar

- `verdict = MANUAL` por el **ritmo humano** (`gap_mean > 2s`).
- Probablemente también `needs_review = true` y, si la secuencia es muy distinta
  de los payloads Mirai, `novel_campaign = true`.
- En Wazuh: alerta **nivel 12** (regla `100102`), destacada en el dashboard.

## Variante "atacante rápido"

Para probar los límites: si pegas todos los comandos de golpe (como haría un
script), el ritmo será de máquina y saldrá `AUTOMATED` aunque seas humano. Es
una limitación honesta del enfoque por ritmo — por eso el Modelo 2 (anomalía)
complementa, marcando el contenido inusual aunque el ritmo engañe.
