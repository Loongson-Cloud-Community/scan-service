# Scan Results Portal

展示 SRPM、RPM 扫描任务、结果摘要和原始产物。页面入口分别为 `/srpm`、`/rpm`。
部署入口见[根目录 README](../README.md)。

## 配置

以下参数填写在根目录 `.env`，示例见 [.env.example](../.env.example)。

| 参数 | 说明 |
| --- | --- |
| `POSTGRES_PASSWORD` | 数据库初始化密码，需与连接串中的密码一致 |
| `DATABASE_URL` | 数据库连接串，栈内地址为 `postgres:5432`；密码含 URL 特殊字符时需编码 |
| `JENKINS_BASE_URL` | 门户读取构建信息和归档产物使用的 Jenkins 地址 |
| `JENKINS_USER` / `JENKINS_TOKEN` | 可读取相关构建及产物的 Jenkins 账号与 API Token |
| `SCAN_RESULTS_PORTAL_URL` | 提供给两个 Agent 的门户地址，默认 `http://scan-results-portal:8080` |
| `SCAN_SERVICE_INGEST_TOKEN` | Jenkins 通知凭据，与调用工具时使用的同名变量一致 |
| `SCAN_SERVICE_OPERATOR_TOKEN` | 维护人员主动同步的独立 Token；留空则禁用主动同步 |
| `OPERATOR_SYNC_RATE_LIMIT_PER_MINUTE` | 每分钟主动同步请求上限，默认 6 |
| `RECENT_BUILD_LIMIT` | 单次主动同步的任务上限，默认 20 |
| `SCAN_SERVICE_TITLE` | 页面标题 |
| `PORTAL_BIND_ADDRESS` / `PORTAL_HTTP_PORT` | 宿主机 HTTP 监听地址及端口，测试默认 `0.0.0.0:8081` |

[config/config.yaml](config/config.yaml) 中的 `ui` 配置页面时区和分页大小，
`artifacts` 配置产物解析、下载和解压限制。

## 数据保存

任务索引和结构化扫描结果保存在 PostgreSQL 的 Docker 命名卷 `scanportal_pgdata`，
备份时需包含该卷。完整扫描产物仍由 Jenkins 归档和保留，不存入门户数据库。

## Jenkins 接入

在 Jenkins 中配置 Secret text 凭据，例如 `scan-service-ingest-token`，值与
`SCAN_SERVICE_INGEST_TOKEN` 一致。Pipeline 将其绑定为同名环境变量后，使用
[RPM Agent](../rpm-scan-agent/README.md#jenkins-接入) 或
[SRPM Agent](../srpm-scan-agent/README.md#jenkins-接入) 提供的 `send-*-event` 工具通知门户，
并用 `archiveArtifacts` 保存扫描结果；无需自行拼接 HTTP 请求。
更多约定见 [Jenkins 接入说明](docs/jenkins-integration.md)。

## 扫描状态

| 状态 | 含义 |
| --- | --- |
| `RUNNING` | 扫描已开始，尚未确认完成 |
| `FINISHED` | 扫描正常结束，结果可用；不代表没有缺陷或漏洞 |
| `FAILED` | 扫描阶段执行失败 |
| `NOT_AVAILABLE` | 扫描或构建已结束，但有效结果暂不可用，例如产物缺失或损坏 |

## 主动同步

用于补偿通知缺失、任务中断等情况，重新核对已登记的 `RUNNING`、`NOT_AVAILABLE` 任务。
不会导入未登记的 Jenkins 构建，也不改动 `FINISHED`、`FAILED` 任务。
同步只供内网维护人员使用，公共页面没有按钮，也不会定时自动执行。

在宿主机执行，输入 `.env` 中的 `SCAN_SERVICE_OPERATOR_TOKEN`。
地址、端口按实际配置替换；下面两条命令分别同步 SRPM 和 RPM：

```bash
read -rsp 'Operator Token: ' SRP_OPERATOR_TOKEN
curl -sS -X POST http://127.0.0.1:8081/api/v1/srpm/sync \
  -H "Authorization: Bearer $SRP_OPERATOR_TOKEN"
curl -sS -X POST http://127.0.0.1:8081/api/v1/rpm/sync \
  -H "Authorization: Bearer $SRP_OPERATOR_TOKEN"
unset SRP_OPERATOR_TOKEN
```

每次最多处理 `RECENT_BUILD_LIMIT` 个任务，积压较多时可分批调用；
Jenkins 不可达或读取失败时，排查后重新执行。
