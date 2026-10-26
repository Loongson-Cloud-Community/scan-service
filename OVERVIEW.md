# 扫描服务框架概览

本文档描述当前扫描服务的整体逻辑框架：各组件的职责与存在形式、彼此的交互
方式，以及与 Jenkins 的交互方式。

## 一、整体形态

| 栈 | 容器 | 说明 |
| --- | --- | --- |
| `scan-service` | `scan-results-portal-gateway`、`scan-results-portal-service`、`scan-results-portal-postgres`、`rpm-scan-agent`、`srpm-scan-agent` | 扫描相关组件 |

与 jenkins 之间**没有共享网络**，Jenkins 通过宿主地址/端口访问；scan-service 栈内
部通过 compose 服务名互访。

## 二、各组件职责与存在形式

### scan-results-portal（门户）

- 存在形式：应用容器，仅在 Compose 私有网络监听 `8080`；公网流量由
  `portal-gateway` 通过 HTTPS 转发；
- 职责：接收扫描事件、经 Jenkins API 拉取并解析扫描结果、把结构化数据写入
  PostgreSQL、页面展示与产物代理下载；
- 它**不执行扫描**，也不读输入包。

### portal-gateway（公网入口）

- 存在形式：Nginx 容器，对外提供 HTTPS，并将 HTTP 请求重定向到 HTTPS；
- 匿名访客只能访问页面、查询 API 和允许公开的产物；
- Jenkins 事件接口不经公网入口，主动同步接口仍由 Portal 校验独立的 operator Token。

### postgres

- 存在形式：容器 + 显式命名卷 `scanportal_pgdata`；
- 职责：门户的持久化层。保存任务索引与结构化扫描结果（`srpm_scan_*` /
  `rpm_scan_*` 表），**不保存原始产物**——原件始终留在 Jenkins。

### rpm-scan-agent

- 存在形式：Jenkins inbound agent 容器，挂载 CVE 漏洞库、agent 工作目录、只读输入目录；
- 职责：执行 cve-bin-tool 扫描，向门户上报事件；
- 输入：宿主 `data/inputs/rpm` → 容器 `/scan-input`（只读），具体文件由
  Pipeline 参数 `RPM_NAMES`（每行一个文件名）指定。

### srpm-scan-agent

- 存在形式：Jenkins inbound agent 容器，自身不含 csmock/mock，通过挂载的 `/var/run/docker.sock`
  为每次扫描起一个 csmock 容器，用完即删；
- 职责：调度 csmock 容器进行扫描，向门户上报事件；
- 输入：宿主 `data/inputs/srpm` → 容器 `/scan-input`（只读），具体文件由
  Pipeline 参数 `SRPM_NAME`（仅文件名）指定。

## 三、交互关系

| # | 链路 | 方向 | 方式与凭据 |
| --- | --- | --- | --- |
| ① | agent ↔ Jenkins | agent **主动出站**注册 | `JENKINS_URL` + `JENKINS_AGENT_SECRET`，`agent.jar -webSocket` |
| ② | 门户 → Jenkins | 门户**主动读** | `JENKINS_BASE_URL` + `JENKINS_USER`/`JENKINS_TOKEN`，读取 job/build/artifact；Jenkins 从不推送 |
| ③ | agent → 门户 | agent 上报事件（只带元数据） | `POST http://scan-results-portal:8080/api/v1/rpm/events`，`Authorization: Bearer <SCAN_SERVICE_INGEST_TOKEN>`（Jenkins 凭据 `scan-service-ingest-token`） |
| ④ | agent → Jenkins | 归档扫描产物 | `archiveArtifacts`，RPM 为 `rpm-scan-artifacts/<build_number>/<sha256>/...`，SRPM 为 `srpm-scan-artifacts/<build_number>/...` |
| ⑤ | 门户 ↔ postgres | 内部 SQL | `DATABASE_URL` 指向服务名 `postgres:5432` |
| ⑥ | 门户 → Jenkins | 产物查看 | 门户自带代理接口，服务端持凭据去 Jenkins 取文件再回传，**访问者无需 Jenkins 凭据** |

关键点：**门户得到的"扫描结果"不是 agent 推过来的，而是它自己按
`job + build` 去 Jenkins 拉归档产物解析出来的**；agent 推送的只是"事件"
（开始 / 结束 / 失败）。

## 四、一次 RPM 扫描的完整时序

1. Pipeline 解析 `RPM_NAMES`，先完成全部文件存在性、文件名和扩展名校验；
2. 对每个唯一 RPM，发送 `started` 事件后调用 `run-rpm-scan` 执行 cve-bin-tool；
3. 单个 RPM 的产物写入
   `rpm-scan-artifacts/<build_number>/<sha256>/`，归档完成后再发送
   `completed` 或 `failed`；
4. 单个 RPM 失败不会阻断后续 RPM，全部处理完成后汇总失败并决定 Job 结果；
5. 门户收到 `completed` 后，经 Jenkins API 取 `scan-manifest.json` 与
   `scan-results.json`，校验 sha256 一致、扫描器退出码 ∈ {0,1}；
6. 解析结果写库，任务置 `FINISHED`；页面展示，产物经门户代理访问。

## 五、状态判定

两种扫描共用四种状态：`RUNNING` / `FINISHED` / `FAILED` / `NOT_AVAILABLE`，
但判定 `FINISHED` 的条件不同：

- SRPM：结果 `.tar.xz` 能正常解压，且包含 6 个预期文件（`scan.ini`、
  `scan-results-summary.txt`、`scan-results.js`、`scan-results.err`、
  `scan-results.html`、`scan.log`），并满足 `scan.ini` 可解析、
  `scan-results-summary.txt` 存在；
- RPM：归档中存在 `scan-manifest.json` 与 `scan-results.json`，校验通过，且
  cve-bin-tool 退出码为 0 或 1（1 表示发现漏洞）。

`FAILED` 由扫描阶段失败的事件触发；结果缺失或不可解析记为
`NOT_AVAILABLE`。

## 六、配置与数据分布

- **配置**：全部集中在 [`scan-service/.env`](.env)（按组件分区），由
  compose 通过变量插值注入。Jenkins 侧不保存
  环境配置，只在 Jenkins 中保存凭据 `scan-service-ingest-token`。
- **宿主数据**：

~~~text
data/jenkins_home                        Jenkins 数据（相对仓库根目录）
scanportal_pgdata                        PostgreSQL 数据（Docker 命名卷）

以下目录由 .env 的「宿主机目录」分区指定（bind mount 进容器）：
RPM_SCAN_CVE_DB_HOST_PATH                cve-bin-tool 漏洞库 → /data/cve-db
RPM_SCAN_INPUT_HOST_PATH                 待扫描 RPM → /scan-input（只读）
RPM_SCAN_AGENT_WORKSPACE_HOST_PATH       rpm agent 工作目录 → /home/jenkins/agent
SRPM_SCAN_INPUT_HOST_PATH                待扫描 SRPM → /scan-input（只读）
SRPM_SCAN_AGENT_WORKSPACE_HOST_PATH      srpm agent 工作目录 → /home/jenkins/agent
~~~

- **产物**：始终只保存在 Jenkins；门户数据库只存索引与结构化字段。

## 七、相关文件

~~~text
scan-service/
├── docker-compose.yml              扫描栈统一编排
├── .env                            扫描栈统一配置
├── gateway/                        Portal HTTPS 网关与证书挂载目录
├── OVERVIEW.md                     本文档
├── scan-results-portal/            门户源码与 Dockerfile
├── rpm-scan-agent/                 RPM 扫描 agent 源码与 Dockerfile
└── srpm-scan-agent/                SRPM 扫描 agent 源码与 Dockerfile
~~~
