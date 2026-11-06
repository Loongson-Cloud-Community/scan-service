FROM lcr.loongnix.cn/loongnix-server/loongnix-server:23.3
RUN sed -i '/\[updates\]/,/enabled=/ s/enabled=1/enabled=0/' /etc/yum.repos.d/Loongnix-Server.repo
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime

ARG CVE_BIN_TOOL_RELEASE=20261106
ARG CVE_BIN_TOOL_ARCHIVE=cve-bin-tool-20261106-la64-py311.tar.gz
ARG JENKINS_AGENT_JAR_URL

ENV PATH="/usr/lib/jvm/jdk-25.0.4/bin:cve-bin-tool/.venv/bin:${PATH}" \
    HOME=/home/jenkins \
    JENKINS_AGENT_WORKDIR=/home/jenkins/agent \
    XDG_CACHE_HOME=/data/cve-db

USER root

RUN dnf install -y \
      ca-certificates \
      cpio \
      curl \
      file \
      gzip \
      rpm \
      python3 \
      tar \
      unzip \
      xz \
      zstd && \
    dnf clean all

RUN mkdir -p /usr/lib/jvm/jdk-25.0.4 && \
    curl --fail --location --retry 5 \
      --output /tmp/jdk25.tar.gz \
      "https://ftp.loongnix.cn/Java/openjdk25/loongson25.5.22-fx-jdk25.0.4_7-linux-loongarch64-glibc2.34.tar.gz" && \
    tar -xzf /tmp/jdk25.tar.gz -C /usr/lib/jvm/jdk-25.0.4 --strip-components=1 && \
    rm -f /tmp/jdk25.tar.gz && \
    mkdir -p /cve-bin-tool /usr/share/jenkins && \
    curl --fail --location --retry 5 \
      --output /tmp/cve-bin-tool.tar.gz \
      "https://github.com/loongarch64-releases/cve-bin-tool/releases/download/${CVE_BIN_TOOL_RELEASE}/${CVE_BIN_TOOL_ARCHIVE}" && \
    tar -xzf /tmp/cve-bin-tool.tar.gz -C /cve-bin-tool && \
    rm -f /tmp/cve-bin-tool.tar.gz && \
    curl --fail --location --retry 5 \
      --output /usr/share/jenkins/agent.jar \
      "${JENKINS_AGENT_JAR_URL}"

ARG AGENT_UID=1000
ARG AGENT_GID=1000
RUN groupadd --gid ${AGENT_GID} jenkins && \
    useradd --uid ${AGENT_UID} --gid ${AGENT_GID} --create-home --shell /bin/bash jenkins && \
    mkdir -p \
      /home/jenkins/agent \
      /data/cve-db && \
    chown -R jenkins:jenkins /home/jenkins /data/cve-db

COPY agent-common /tmp/agent-common
# Event commands use the system interpreter, independent of the scanner venv.
RUN /usr/bin/python3 /tmp/agent-common/install.py && rm -rf /tmp/agent-common

COPY rpm-scan-agent/scripts/run-rpm-scan /usr/local/bin/run-rpm-scan
COPY rpm-scan-agent/libexec/rpm-scan-agent/scan /usr/local/libexec/rpm-scan-agent/scan
COPY rpm-scan-agent/scripts/send-rpm-event /usr/local/bin/send-rpm-event
COPY rpm-scan-agent/scripts/update-cve-db /usr/local/bin/update-cve-db
COPY rpm-scan-agent/scripts/jenkins-agent-entrypoint /usr/local/bin/jenkins-agent-entrypoint

RUN chmod 0755 \
      /usr/local/bin/run-rpm-scan \
      /usr/local/bin/send-rpm-event \
      /usr/local/bin/update-cve-db \
      /usr/local/bin/jenkins-agent-entrypoint

USER jenkins
WORKDIR /home/jenkins/agent

ENTRYPOINT ["jenkins-agent-entrypoint"]
