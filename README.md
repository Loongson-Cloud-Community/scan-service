# Scan Service

扫描服务栈。包含与软件包扫描有关的全部组件，由同目录下的
`docker-compose.yml` 统一编排。Jenkins 不在此栈内。

各组件的职责、存在形式与交互关系（含与 Jenkins 的交互）见
[OVERVIEW.md](OVERVIEW.md)。

## 组件

| 服务 | 容器名称 | 作用 |
| --- | --- | --- |
| portal-gateway | scan-results-portal-gateway | Portal 公网 HTTPS 入口和公开/内部路由隔离 |
| scan-results-portal | scan-results-portal-service | 扫描结果展示门户 + Jenkins 事件接收 API |
| postgres | scan-results-portal-postgres | 任务索引与结构化扫描结果存储 |
| rpm-scan-agent | rpm-scan-agent | Jenkins inbound agent，执行 cve-bin-tool RPM 漏洞扫描 |
| srpm-scan-agent | srpm-scan-agent | Jenkins inbound agent，调度一次性 csmock 容器执行 SRPM 扫描 |

## 目录结构

~~~text
scan-service/
├── docker-compose.yml              本栈的统一编排文件
├── .env                            本栈统一配置（按组件分区，参考 .env.example）
├── gateway/                        Portal HTTPS 入口配置与证书挂载目录
├── scan-results-portal/            门户源码、Dockerfile、config、migrations
├── rpm-scan-agent/                 RPM 扫描 agent 源码与 Dockerfile
└── srpm-scan-agent/                SRPM 扫描 agent 源码与 Dockerfile
~~~

所有配置集中在本目录的 .env，由 compose 通过变量插值注入到对应容器。

## 启动

启动前将 Portal 公网地址对应的 PEM 证书链和私钥分别放到
`gateway/tls/tls.crt` 与 `gateway/tls/tls.key`。证书文件不会被 Git 跟踪。

~~~bash
cp .env.example .env
docker compose up -d --build
~~~

只重建/重启单个组件：

~~~bash
docker compose up -d --build scan-results-portal
docker compose up -d rpm-scan-agent
~~~

## 配置

全部配置位于本目录的 `.env`，用注释按组件分区：

| 分区 | 内容 |
| --- | --- |
| 外部 Jenkins | `JENKINS_URL`（agent 注册）、`JENKINS_BASE_URL`（门户读取）、`JENKINS_AGENT_JAR_URL`（agent 构建参数） |
| postgres | `POSTGRES_PASSWORD` |
| scan-results-portal | `DATABASE_URL`、`JENKINS_USER/TOKEN`、`SCAN_SERVICE_INGEST_TOKEN`、`SCAN_SERVICE_OPERATOR_TOKEN`、`RECENT_BUILD_LIMIT`、页面标题等 |
| rpm-scan-agent | `RPM_SCAN_AGENT_NAME/SECRET`、`CVE_UPDATE_MODE`、`CVE_DB_UPDATE_LOCK_TIMEOUT`、`CVE_DB_UPDATE_TIMEOUT` |
| srpm-scan-agent | `SRPM_SCAN_AGENT_NAME/SECRET`、`CSMOCK_IMAGE`、`MOCK_CONFIG`、`CSMOCK_TOOLS`、`DOCKER_GID` |

`POSTGRES_PASSWORD` 与 `DATABASE_URL` 中的密码需要保持一致。
`SCAN_RESULTS_PORTAL_URL` 由两个扫描 agent 共用。

## 交互规则

- 栈内组件在同一个 compose 网络上，通过服务名互相访问：
  - 门户访问数据库：`postgres:5432`
  - 扫描 agent 回传扫描事件到门户：`http://scan-results-portal:8080`
- Jenkins 在栈外，通过各组件的 .env 访问：
  - agent 注册：`JENKINS_URL`
  - 门户读取构建与产物：`JENKINS_BASE_URL`
- 对外只暴露 `portal-gateway`：HTTP `8080` 跳转到 HTTPS `8081`；Portal
  应用容器不再直接映射宿主端口。

页面和只读 API 允许匿名访问。主动同步不显示在公共页面中，只允许内部运维携带
`SCAN_SERVICE_OPERATOR_TOKEN` 调用。

产物查看和下载由 Portal 流式代理，不再把完整文件读入内存。解析与压缩包展开
上限配置在 `scan-results-portal/config/config.yaml` 的 `artifacts` 分区；公网
gateway 还会限制单一来源的下载速率和并发连接数。

## 持久化数据

| 数据 | 位置 |
| --- | --- |
| PostgreSQL | Docker 卷 `scanportal_pgdata` |
| cve-bin-tool 漏洞库 | `.env` 的 `RPM_SCAN_CVE_DB_HOST_PATH` |
| rpm agent 工作目录 | `.env` 的 `RPM_SCAN_AGENT_WORKSPACE_HOST_PATH` |
| srpm agent 工作目录 | `.env` 的 `SRPM_SCAN_AGENT_WORKSPACE_HOST_PATH` |
