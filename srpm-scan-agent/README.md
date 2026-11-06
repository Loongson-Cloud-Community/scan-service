# SRPM Scan Agent

LoongArch64 Jenkins inbound agent，用 `csmock` 扫描源码包（SRPM）。

本组件是 `scan-service` 扫描服务栈的一部分：镜像构建、容器启动与运行时配置
由上级目录的 `docker-compose.yml` 与 `.env` 统一管理。

持久化（路径来自 `scan-service/.env` 的「宿主机目录」分区）：

~~~text
SRPM_SCAN_AGENT_WORKSPACE_HOST_PATH    agent 工作目录，挂到容器 /home/jenkins/agent
SRPM_SCAN_INPUT_HOST_PATH              待扫描 SRPM，只读挂到容器 /scan-input
~~~

## 设计：调度型 agent + 一次性扫描容器

csmock 会在 mock 里构建源码包，需要 `SYS_ADMIN`。因此本 agent 自己**不含**
csmock/mock，而是：

1. 作为 Jenkins inbound agent 接收构建；
2. 通过挂进来的 `/var/run/docker.sock` 调起一个**一次性 csmock 容器**完成扫描；
3. 扫描产物落到宿主工作目录（与 agent 挂载一致），容器用完即删；
4. 由 pipeline 把产物归档到 Jenkins、把事件上报给门户。

这样特权只给真正跑 mock 的那个短命容器，agent 本身保持精简。

## 并发模型

本组件**不挂载 mock 缓存目录**，每个一次性容器在自己的文件系统里初始化
chroot，`buildroot.lock` 各自独立，因此**多个 SRPM 扫描可以并行**。

代价：

- **每次扫描都要初始化 chroot**：下载并安装整套构建环境；
- 容器**不保留**构建缓存，唯一痕迹是落到宿主工作目录的 `.tar.xz`。

## 配置

运行时配置位于 `scan-service/.env` 的 `srpm-scan-agent` 分区，由 compose 注入容器：

| 键 | 说明 |
| --- | --- |
| `SRPM_SCAN_AGENT_NAME` / `SRPM_SCAN_AGENT_SECRET` | Jenkins permanent agent 名称与 inbound secret |
| `CSMOCK_IMAGE` | 一次性扫描用的 csmock 镜像 |
| `MOCK_CONFIG` | mock 配置，默认 `loongnix-server-23-loongarch64` |
| `CSMOCK_TOOLS` | 启用的检查器，默认 `cppcheck,clang,gcc,shellcheck` |
| `DOCKER_GID` | 宿主 `docker.sock` 的属组 gid |

## 启动

在 `scan-service` 目录执行：

~~~bash
docker compose up -d --build srpm-scan-agent
~~~

## Jenkins 侧

在 Jenkins 上创建 permanent agent srpm-scan-agent-01，标签为 srpm-scan， 并把其 inbound-agent secret 写入 scan-service/.env 的 `SRPM_SCAN_AGENT_SECRET`。

Pipeline 参数 `SRPM_NAME` 只填写完整 SRPM 文件名，不包含目录；`run-srpm-scan`
会在只读挂载目录 `/scan-input` 下解析该文件。
