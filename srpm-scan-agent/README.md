# SRPM Scan Agent

Jenkins 入站 Agent，调用一次性 csmock 容器扫描源码包。
部署入口见[根目录 README](../README.md)。

## 配置与持久化

以下参数填写在根目录 `.env`，示例见 [.env.example](../.env.example)。

| 参数 | 说明 |
| --- | --- |
| `AGENT_UID` / `AGENT_GID` | 构建镜像时创建 Agent 用户的 UID/GID，与宿主工作目录权限匹配 |
| `JENKINS_URL` | Agent 连接 Jenkins 的地址 |
| `JENKINS_AGENT_JAR_URL` | 构建镜像时下载 agent.jar 的地址 |
| `SRPM_SCAN_AGENT_NAME` / `SRPM_SCAN_AGENT_SECRET` | Jenkins 入站节点名称及对应 Secret |
| `SCAN_RESULTS_PORTAL_URL` | 事件回传地址，默认 `http://scan-results-portal:8080` |
| `CSMOCK_IMAGE` | 扫描使用的 csmock 镜像 |
| `MOCK_CONFIG` | mock 配置名称，默认 `loongnix-server-23-loongarch64` |
| `CSMOCK_TOOLS` | 逗号分隔的检查器，默认 `cppcheck,clang,gcc,shellcheck` |
| `DOCKER_GID` | 宿主机 `docker.sock` 的属组 GID，供 Agent 访问 Docker |
| `SRPM_SCAN_INPUT_HOST_PATH` | 待扫描包目录，只读挂载到 `/scan-input` |
| `SRPM_SCAN_AGENT_WORKSPACE_HOST_PATH` | Agent 工作区与扫描输出，挂载到 `/home/jenkins/agent` |

工作目录应允许 `AGENT_UID:AGENT_GID` 读写；输入目录只需可读、可遍历。

## Jenkins 接入

在 Jenkins 中创建与 `SRPM_SCAN_AGENT_NAME` 同名的入站节点，将 Secret 填入配置，Pipeline 选择该节点执行。
Agent 提供以下命令：

| 命令 | 用途与参数 |
| --- | --- |
| `run-srpm-scan SRPM_NAME [OUTPUT_DIR]` | 扫描 `/scan-input` 下的单个 `.src.rpm`；包名不含目录，输出目录默认 `srpm-scan-artifacts`，须位于 Agent 工作目录内 |
| `run-srpm-scan --dry-run SRPM_NAME [OUTPUT_DIR]` | 仅打印扫描容器命令，不执行扫描 |
| `send-srpm-event started\|completed\|failed` | 上报扫描状态；必填 `--srpm-name`；可选 `--event-time`、`--csmock-exit-code` |
| `send-srpm-event replay` | 补发尚未确认的通知，不需要包名或当前构建参数 |

通知命令使用 Jenkins 提供的 `JOB_NAME`、`BUILD_NUMBER`。在 Pipeline 中通过凭据绑定
提供 `SCAN_SERVICE_INGEST_TOKEN`，其值与门户配置一致；`SCAN_RESULTS_PORTAL_URL`
已由容器配置提供。

接入顺序为：发送 `started` → 扫描 → 用 Jenkins `archiveArtifacts` 归档 → 发送
`completed`；扫描执行失败则发送 `failed`。通知失败可用 `replay` 补发。
产物目录使用 `srpm-scan-artifacts/<构建号>/`，完整接入约定见
[Jenkins 接入说明](../scan-results-portal/docs/jenkins-integration.md)。
