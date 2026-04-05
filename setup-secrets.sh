#!/bin/bash
# setup-secrets.sh v2 — Run ONCE before docker-compose up

set -e

mkdir -p secrets

if [ ! -f secrets/db_password.txt ]; then
  openssl rand -base64 32 | tr -dc 'A-Za-z0-9!@#$%' | head -c 32 > secrets/db_password.txt
  echo "✓ Generated db_password.txt"
fi

# jwt_secret kept for backward compat — RSA keys are now generated at runtime
if [ ! -f secrets/jwt_secret.txt ]; then
  openssl rand -base64 64 | tr -dc 'A-Za-z0-9' | head -c 64 > secrets/jwt_secret.txt
  echo "✓ Generated jwt_secret.txt (legacy — RSA keys auto-generated at startup)"
fi

chmod 600 secrets/*.txt

echo ""
echo "✓ Secrets ready."
echo ""
echo "RSA keypair: auto-generated on first backend startup → stored in nexus_keys volume"
echo "JWKS endpoint: http://localhost/.well-known/jwks.json (after launch)"
echo ""
echo "Run: docker-compose up --build -d"
echo "Login: admin@nexus.local / ChangeMe!9"
