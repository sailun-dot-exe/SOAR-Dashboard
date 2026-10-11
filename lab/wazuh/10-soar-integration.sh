#!/bin/bash
# Runs inside wazuh-manager before Wazuh starts (see /entrypoint-scripts in the image).
set -euo pipefail
CONF=/var/ossec/etc/ossec.conf
: "${SOAR_HOOK_URL:?SOAR_HOOK_URL must be set}"
: "${SOAR_API_TOKEN:?SOAR_API_TOKEN must be set}"
sed -i "s|__SOAR_HOOK_URL__|${SOAR_HOOK_URL}|; s|__SOAR_API_TOKEN__|${SOAR_API_TOKEN}|" "$CONF"
chown root:wazuh /var/ossec/integrations/custom-soar
chmod 750 /var/ossec/integrations/custom-soar
chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
chmod 660 /var/ossec/etc/rules/local_rules.xml
echo "SOAR integration configured -> ${SOAR_HOOK_URL}"
