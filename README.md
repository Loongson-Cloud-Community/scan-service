# Scan Service

面向 Jenkins 的软件包扫描服务，支持 SRPM 源码扫描、RPM 漏洞扫描及结果展示。

## 组件

| 组件 | 用途与使用说明 |
| --- | --- |
| [scan-results-portal](scan-results-portal/README.md) | 展示扫描任务、结果及产物 |
| PostgreSQL | 保存门户数据，配置与持久化说明见 [scan-results-portal](scan-results-portal/README.md) |
| [rpm-scan-agent](rpm-scan-agent/README.md) | Jenkins 入站 Agent，使用 cve-bin-tool 扫描 RPM |
| [srpm-scan-agent](srpm-scan-agent/README.md) | Jenkins 入站 Agent，调用 csmock 扫描 SRPM |

## 目录结构

```text
scan-service/
├── docker-compose.yml       统一编排
├── .env.example             配置模板
├── common/                  公共代码
├── scan-results-portal/     门户
├── rpm-scan-agent/          RPM 扫描 Agent
├── srpm-scan-agent/         SRPM 扫描 Agent
├── OVERVIEW.md              框架与交互说明
└── PORTAL-DEPLOYMENT.md     部署入口约定
```

三个组件均为本仓库的普通目录，统一版本管理。

## 启动

1. 复制配置模板：

   ```bash
   cp .env.example .env
   ```

2. 按各组件 README 填写 `.env`、准备挂载目录及权限，并在 Jenkins 中准备对应的入站 Agent。
3. 在本目录启动服务：

   ```bash
   docker compose up -d --build
   ```

默认访问 `http://<宿主机>:8081/srpm` 或 `/rpm`，仅用于受控内网测试。

### 重要：首次 RPM 扫描前，按 RPM Agent README 初始化漏洞库。

## 更多

组件交互与运行原理请阅读 [OVERVIEW.md](OVERVIEW.md)。
[PORTAL-DEPLOYMENT.md](PORTAL-DEPLOYMENT.md) 是为后续接入统一公网入口预留的临时部署约定文件；
当前测试环境仍使用 HTTP。
