#!/usr/bin/env bash
#
# Provisiona el laboratorio en AWS:
#   - manager : Wazuh all-in-one (manager+indexer+dashboard)   m7i.large
#   - victim  : Cowrie + servicio de inferencia + agente Wazuh  m7i.large
#
# Requiere aws-cli configurado. NO expongas esto a producción: es un lab.
# Todo queda etiquetado Project=ssh-classifier-lab para borrarlo con teardown.sh
#
set -euo pipefail
REGION="${REGION:-us-east-1}"
PROJECT=ssh-classifier-lab
KEY_NAME=${PROJECT}-key
KEY_FILE=$HOME/.ssh/${KEY_NAME}.pem
SG_NAME=${PROJECT}-sg
MANAGER_TYPE=${MANAGER_TYPE:-m7i-flex.large}   # 8 GB, elegible free-tier
VICTIM_TYPE=${VICTIM_TYPE:-m7i-flex.large}     # 8 GB, elegible free-tier

MY_IP=$(curl -s https://checkip.amazonaws.com)/32
echo "Tu IP pública (para acceso admin/dashboard): $MY_IP"
echo "Región: $REGION"

AMI=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id \
  --query 'Parameters[0].Value' --output text)
echo "AMI Ubuntu 22.04: $AMI"

echo "==> Key pair"
if ! aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" &>/dev/null; then
  mkdir -p "$HOME/.ssh"
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  echo "   creada: $KEY_FILE"
fi

echo "==> Security group"
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters Name=group-name,Values="$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  SG_ID=$(aws ec2 create-security-group --region "$REGION" --group-name "$SG_NAME" \
    --description "$PROJECT" --query 'GroupId' --output text)
  # admin SSH y dashboard solo desde tu IP
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --protocol tcp --port 22 --cidr "$MY_IP"
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --protocol tcp --port 443 --cidr "$MY_IP"
  # honeypot Cowrie (2222) abierto: recibe tus ataques (y, si quieres, internet)
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --protocol tcp --port 2222 --cidr 0.0.0.0/0
  # comunicación interna del SG (agente Wazuh -> manager 1514/1515)
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --ip-permissions "IpProtocol=tcp,FromPort=1514,ToPort=1515,UserIdGroupPairs=[{GroupId=$SG_ID}]"
  echo "   creado: $SG_ID"
fi

echo "==> Instancia MANAGER ($MANAGER_TYPE) con Wazuh all-in-one"
cat > /tmp/manager-userdata.sh <<'UD'
#!/bin/bash
sysctl -w vm.max_map_count=262144
# nota: la ruta /4.x/ dejó de existir; usar versión explícita
curl -fsSL -o /root/wazuh-install.sh https://packages.wazuh.com/4.13/wazuh-install.sh
bash /root/wazuh-install.sh -a -i >/var/log/wazuh-install.log 2>&1
UD
MANAGER_ID=$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" \
  --instance-type "$MANAGER_TYPE" --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=40}' \
  --user-data file:///tmp/manager-userdata.sh \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT},{Key=Name,Value=$PROJECT-manager}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "   $MANAGER_ID"

echo "==> Instancia VICTIM ($VICTIM_TYPE)"
VICTIM_ID=$(aws ec2 run-instances --region "$REGION" --image-id "$AMI" \
  --instance-type "$VICTIM_TYPE" --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --block-device-mappings 'DeviceName=/dev/sda1,Ebs={VolumeSize=20}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Project,Value=$PROJECT},{Key=Name,Value=$PROJECT-victim}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "   $VICTIM_ID"

echo "==> Esperando IPs públicas..."
aws ec2 wait instance-running --region "$REGION" --instance-ids "$MANAGER_ID" "$VICTIM_ID"
MANAGER_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$MANAGER_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
VICTIM_IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$VICTIM_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<EOF

============================================================
  LAB DESPLEGADO
============================================================
  Key:        $KEY_FILE
  MANAGER:    $MANAGER_IP   (dashboard https://$MANAGER_IP  user: admin)
              -> Wazuh tarda ~10 min en instalarse (ver /var/log/wazuh-install.log)
              -> la contraseña admin está en wazuh-install-files.tar en el manager
  VICTIM:     $VICTIM_IP    (Cowrie en :2222)

  SIGUIENTE (ver lab/README.md):
  1) Copiar modelos + servicio a la víctima:
       scp -i $KEY_FILE -r ../inference/infer_service.py \\
           ../../models ubuntu@$VICTIM_IP:/tmp/
  2) En la víctima: mover a /opt/ssh-classifier y correr setup_victim.sh
       WAZUH_MANAGER=$MANAGER_IP bash setup_victim.sh
  3) Atacar: bash ../attacks/auto_attack.sh $VICTIM_IP
============================================================
EOF
