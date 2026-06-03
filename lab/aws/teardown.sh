#!/usr/bin/env bash
#
# Destruye TODO el laboratorio (instancias, security group, key pair).
# IMPORTANTE: ejecútalo al terminar para no seguir pagando.
#
set -euo pipefail
REGION="${REGION:-us-east-1}"
PROJECT=ssh-classifier-lab
KEY_NAME=${PROJECT}-key
SG_NAME=${PROJECT}-sg

echo "==> Terminando instancias del proyecto $PROJECT"
IDS=$(aws ec2 describe-instances --region "$REGION" \
  --filters Name=tag:Project,Values="$PROJECT" \
            Name=instance-state-name,Values=pending,running,stopping,stopped \
  --query 'Reservations[].Instances[].InstanceId' --output text)
if [ -n "$IDS" ]; then
  aws ec2 terminate-instances --region "$REGION" --instance-ids $IDS
  aws ec2 wait instance-terminated --region "$REGION" --instance-ids $IDS
  echo "   terminadas: $IDS"
fi

echo "==> Borrando security group"
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters Name=group-name,Values="$SG_NAME" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
[ -n "$SG_ID" ] && [ "$SG_ID" != "None" ] && \
  aws ec2 delete-security-group --region "$REGION" --group-id "$SG_ID" && \
  echo "   borrado: $SG_ID"

echo "==> Borrando key pair"
aws ec2 delete-key-pair --region "$REGION" --key-name "$KEY_NAME" || true

echo "Laboratorio eliminado. Verifica en la consola que no quede nada cobrando."
