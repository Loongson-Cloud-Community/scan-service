# Agent 公共事件客户端

`agent-common/scan_agent_events` 是 RPM、SRPM Agent 共用的标准库 Python 包：

- `transport`：HTTP 重试、错误分类、Retry-After 和任务确认校验。
- `outbox`：持久化、并发写入、确认删除与公平批次选择。
- `delivery`：目标配置、发送与恢复的完整流程。

两个 `send-*-event` 命令仅保留各自的参数与事件字段组装。Portal API、退出码、
命令参数、认证和 outbox 的路径及数据库格式不变，旧的未交付事件可继续重发。
不新增运行服务、必填环境变量或外部 Pipeline 步骤。

## 构建与测试

Agent 镜像仍分别构建，但构建上下文统一为 `scan-service` 根目录，以便安装同一份
公共源码。继续在根目录使用原有 `docker compose build rpm-scan-agent srpm-scan-agent`
即可；不要再把单独的 Agent 子目录作为 Docker 构建上下文。

根目录 `.dockerignore` 只允许 Agent 构建输入，排除敏感配置、数据目录与 Git 元数据。
公共包随镜像安装到对应 Python 的 import 目录，不需要运行时挂载公共源码或配置
`PYTHONPATH`，也不依赖 pip、额外基础镜像或软件源。
事件命令使用镜像的系统 Python，与扫描工具自己的虚拟环境分离。

公共契约测试集中在 `agent-common/tests`，同一套测试覆盖两个命令；扫描执行测试仍
保留在各自 Agent 中。可基于已有 Agent 镜像构建无网络测试镜像：

```sh
docker build --network none -f agent-common/tests/Dockerfile \
  --build-arg AGENT_IMAGE=rpm-scan-agent:latest -t scan-agent-events-test:rpm .
```

使用该镜像，在临时容器中将项目只读挂载到 `/src`，运行：

```text
python3 -m unittest discover -s /src/agent-common/tests
```

SRPM 镜像使用同样方式验证。测试不连接生产 Portal，也不启动 Jenkins。
