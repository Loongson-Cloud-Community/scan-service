# RPM Scan Agent

Jenkins 入站 Agent，使用 cve-bin-tool 扫描 RPM。部署入口见[根目录 README](../README.md)。

## 配置与持久化

以下参数填写在根目录 `.env`，示例见 [.env.example](../.env.example)。

| 参数 | 说明 |
| --- | --- |
| `AGENT_UID` / `AGENT_GID` | 构建镜像时创建 Agent 用户的 UID/GID，与宿主可写目录权限匹配 |
| `JENKINS_URL` | Agent 连接 Jenkins 的地址 |
| `JENKINS_AGENT_JAR_URL` | 构建镜像时下载 agent.jar 的地址 |
| `RPM_SCAN_AGENT_NAME` / `RPM_SCAN_AGENT_SECRET` | Jenkins 入站节点名称及对应 Secret |
| `SCAN_RESULTS_PORTAL_URL` | 事件回传地址，默认 `http://scan-results-portal:8080` |
| `CVE_UPDATE_MODE` | 固定为 `never`，扫描时不执行漏洞库更新 |
| `CVE_DB_UPDATE_LOCK_TIMEOUT` | 更新工具等待漏洞库锁的秒数，默认 3600；0 表示不等待 |
| `CVE_DB_UPDATE_TIMEOUT` | 漏洞库更新的总时长上限（秒），默认 3600；0 表示不限时 |
| `RPM_SCAN_INPUT_HOST_PATH` | 待扫描包目录，只读挂载到 `/scan-input` |
| `RPM_SCAN_AGENT_WORKSPACE_HOST_PATH` | Agent 工作区与扫描输出，挂载到 `/home/jenkins/agent` |
| `RPM_SCAN_CVE_DB_HOST_PATH` | 漏洞库与缓存，挂载到 `/data/cve-db` |

工作目录和漏洞库（含已有文件）应允许 `AGENT_UID:AGENT_GID` 读写；输入目录只需可读、可遍历。

## Jenkins 接入

在 Jenkins 中创建与 `RPM_SCAN_AGENT_NAME` 同名的入站节点，将 Secret 填入配置，Pipeline 选择该节点执行。
Agent 提供以下命令：

| 命令 | 用途与参数 |
| --- | --- |
| `run-rpm-scan RPM_NAME OUTPUT_DIRECTORY` | 扫描 `/scan-input` 下的单个 RPM；包名不含目录，输出目录由调用方指定 |
| `send-rpm-event started\|completed\|failed` | 上报扫描状态；必填 `--rpm-name`、`--scan-key`、`--rpm-sha256`；可选 `--event-time`、`--cbt-exit-code` |
| `send-rpm-event replay` | 补发尚未确认的通知，不需要包名或当前构建参数 |

通知命令使用 Jenkins 提供的 `JOB_NAME`、`BUILD_NUMBER`。在 Pipeline 中通过凭据绑定
提供 `SCAN_SERVICE_INGEST_TOKEN`，其值与门户配置一致；`SCAN_RESULTS_PORTAL_URL`
已由容器配置提供。`--scan-key` 与 `--rpm-sha256` 均使用待扫描 RPM 的 SHA256。

接入顺序为：发送 `started` → 扫描 → 用 Jenkins `archiveArtifacts` 归档 → 发送
`completed`；扫描执行失败则发送 `failed`。通知失败可用 `replay` 补发。
产物目录使用 `rpm-scan-artifacts/<构建号>/<SHA256>/`，完整接入约定见
[Jenkins 接入说明](../scan-results-portal/docs/jenkins-integration.md)。

## 更新漏洞库

首次扫描前及后续更新，固定使用 `update-cve-db`，不要在扫描命令中开启更新。
在项目根目录执行：

```bash
docker compose --profile cve-db run --rm cve-db-update
```

也可在已运行的 Agent 中执行 `docker exec rpm-scan-agent update-cve-db`。
