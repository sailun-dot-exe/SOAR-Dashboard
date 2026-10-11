# Vulnerable lab target: Ubuntu + sshd (password auth) + nginx + Wazuh agent.
FROM ubuntu:22.04

ARG WAZUH_VERSION=4.14.8-1
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      openssh-server rsyslog nginx iptables sudo curl ca-certificates gnupg procps iproute2 \
      netcat-openbsd lsb-release \
 && curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      > /etc/apt/sources.list.d/wazuh.list \
 && apt-get update \
 && WAZUH_MANAGER=wazuh-manager WAZUH_AGENT_NAME=target-victim \
      apt-get install -y --no-install-recommends wazuh-agent=${WAZUH_VERSION} \
 && rm -rf /var/lib/apt/lists/*

# rsyslog in a container: no kernel log access.
RUN sed -i 's/^module(load="imklog"/#module(load="imklog"/' /etc/rsyslog.conf

# Deliberately weak target account + a dedicated, key-only responder account for the SOAR.
RUN useradd -m -s /bin/bash admin && echo 'admin:Winter2026!Corp' | chpasswd \
 && useradd -m -s /bin/bash soar && passwd -l soar \
 && echo 'soar ALL=(root) NOPASSWD: /usr/sbin/iptables, /usr/sbin/ip6tables' > /etc/sudoers.d/soar \
 && chmod 440 /etc/sudoers.d/soar \
 && mkdir -p /run/sshd /home/soar/.ssh && chown soar:soar /home/soar/.ssh && chmod 700 /home/soar/.ssh

COPY sshd_config /etc/ssh/sshd_config
COPY agent-localfiles.xml /tmp/agent-localfiles.xml
RUN cat /tmp/agent-localfiles.xml >> /var/ossec/etc/ossec.conf && rm /tmp/agent-localfiles.xml
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 80
ENTRYPOINT ["/entrypoint.sh"]
