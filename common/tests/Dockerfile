# Packaging smoke tests only. Use an existing agent image without downloading tools.
ARG AGENT_IMAGE
FROM ${AGENT_IMAGE}
USER root
COPY common /tmp/common
RUN /usr/bin/python3 /tmp/common/install.py && rm -rf /tmp/common
COPY rpm-scan-agent/scripts/send-rpm-event /usr/local/bin/send-rpm-event
COPY srpm-scan-agent/scripts/send-srpm-event /usr/local/bin/send-srpm-event
RUN chmod 0755 /usr/local/bin/send-rpm-event /usr/local/bin/send-srpm-event
# Inspect the actual filtered context, not an approximation of dockerignore rules.
COPY . /filtered-context
USER jenkins
