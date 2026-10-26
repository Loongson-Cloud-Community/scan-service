# Scan Service

扫描服务栈。包含与软件包扫描有关的全部组件，由同目录下的
`docker-compose.yml` 统一编排。Jenkins 不在此栈内。

各组件的职责、存在形式与交互关系（含与 Jenkins 的交互）见
[OVERVIEW.md](OVERVIEW.md)。

## 组件

| 服务 | 容器名称 | 作用 |
| --- | --- | --- |
| scan-results-portal | scan-results-portal-service | 扫描结果展示门户 + Jenkins 事件接收 API |
| postgres | scan-results-portal-postgres | 任务索引与结构化扫描结果存储 |
| rpm-scan-agent | rpm-scan-agent | Jenkins inbound agent，执行 cve-bin-tool RPM 漏洞扫描 |
| srpm-scan-agent | srpm-scan-agent | Jenkins inbound agent，调度一次性 csmock 容器执行 SRPM 扫描 |

## 目录结构

~~~text
scan-service/
├── docker-compose.yml              本栈的统一编排文件
├── .env                            本栈统一配置（按组件分区，参考 .env.example）
├── PORTAL-DEPLOYMENT.md            Portal 测试环境说明与生产环境的部署约定
├── scan-results-portal/            门户源码、Dockerfile、config、migrations
├── rpm-scan-agent/                 RPM 扫描 agent 源码与 Dockerfile
└── srpm-scan-agent/                SRPM 扫描 agent 源码与 Dockerfile
~~~

所有配置集中在本目录的 .env，由 compose 通过变量插值注入到对应容器。

## 启动

~~~bash
cp .env.example .env
docker compose up -d --build
~~~

测试阶段由 Portal 容器直接提供 HTTP 服务，默认地址为
`http://<宿主机>:8081` (仅用于受控内网测试)。

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
- 测试阶段，Portal 通过宿主机 `8081` 端口提供 HTTP 访问。
- 生产阶段由公网统一入口负责域名与 TLS，并通过内网
  HTTP 转发到 Portal；完整接口和访问控制约定见
  [PORTAL-DEPLOYMENT.md](PORTAL-DEPLOYMENT.md)。

页面和只读 API 允许匿名访问。主动同步不显示在公共页面中，只允许内网携带
`SCAN_SERVICE_OPERATOR_TOKEN` 调用。

产物查看和下载由 Portal 流式代理，不把完整文件读入内存。解析与压缩包展开
上限配置在 `scan-results-portal/config/config.yaml` 的 `artifacts` 分区；
生产环境中还应由公网入口限制单一来源的请求速率和并发连接数。

## 持久化数据

| 数据 | 位置 |
| --- | --- |
| PostgreSQL | Docker 卷 `scanportal_pgdata` |
| cve-bin-tool 漏洞库 | `.env` 的 `RPM_SCAN_CVE_DB_HOST_PATH` |
| rpm agent 工作目录 | `.env` 的 `RPM_SCAN_AGENT_WORKSPACE_HOST_PATH` |
| srpm agent 工作目录 | `.env` 的 `SRPM_SCAN_AGENT_WORKSPACE_HOST_PATH` |
