#!/bin/bash

is_empty_or_blank() {
    [[ -z "${1// }" ]]
}

read -p "Enter CLIENT_ID: " client_id
read -p "Enter CLIENT_SECRET: " client_secret

read -p "Enter GITHUB_WEBHOOK_SECRET: " webhook_github_secret

if is_empty_or_blank "$webhook_github_secret"; then
    webhook_github_secret="$(openssl rand -hex 32)"
    echo "GITHUB_WEBHOOK_SECRET: $webhook_github_secret"
fi

# Replace CLIENT_ID and CLIENT_SECRET in a file
sed "s/CLIENT_ID/$client_id/g; s/CLIENT_SECRET/$client_secret/g; s/GITHUB_WEBHOOK_SECRET/$webhook_github_secret/g;" values.template.yaml > values.yaml
