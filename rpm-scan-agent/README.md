# RPM Scan Agent

LoongArch64 Jenkins inbound agent，用 `cve-bin-tool` 扫描 RPM 包。

本组件是 `scan-service` 扫描服务栈的一部分。
镜像构建、容器启动与运行时配置都由上级目录的 `docker-compose.yml` 与
`.env` 统一管理。

持久化（路径来自 `scan-service/.env` 的「宿主机目录」分区）：

~~~text
RPM_SCAN_CVE_DB_HOST_PATH             漏洞库，挂到容器 /data/cve-db
RPM_SCAN_AGENT_WORKSPACE_HOST_PATH    agent 工作目录，挂到容器 /home/jenkins/agent
RPM_SCAN_INPUT_HOST_PATH              待扫描 RPM，只读挂到容器 /scan-input
~~~

## 配置

运行时配置位于 `scan-service/.env` 的 `rpm-scan-agent` 分区，由 compose
注入容器：

| 键 | 说明 |
| --- | --- |
| `RPM_SCAN_AGENT_NAME` / `RPM_SCAN_AGENT_SECRET` | Jenkins permanent agent 名称与 inbound secret |
| `CVE_UPDATE_MODE` | 扫描时的漏洞库更新模式，始终保持为 never |
| `CVE_DB_UPDATE_LOCK_TIMEOUT` | 更新漏洞库时的锁等待上限 |
| `CVE_DB_UPDATE_TIMEOUT` | 更新漏洞库本身的总时长上限 |

## 启动

在 `scan-service` 目录执行：

~~~bash
docker compose up -d --build rpm-scan-agent
~~~

## 更新漏洞库

扫描固定使用 `--update never`：**扫描只读漏洞库，从不更新**。避免多任务同时
更新漏洞库发生冲突。

漏洞库的创建与更新由 `update-cve-db` 完成：它对同一个库目录执行 
`cve-bin-tool --update daily`（当距离上一次更新时间超过一天时进行增量更新），
并通过文件锁与扫描互斥——扫描持**共享锁**（多个扫描可并行），更新持**排他锁**
（会等所有正在运行的扫描结束）。

执行方式：

~~~bash
# 推荐：一次性容器，与 agent 容器的生命周期无关
docker compose --profile cve-db run --rm cve-db-update

# 或者直接进 agent 容器执行
docker exec rpm-scan-agent update-cve-db
~~~

更新结束后，若日志结尾出现 ERROR `InsufficientArgs: Please specify a
directory to scan or an input`（cve-bin-tool 退出码 24）：这是"只更新库、没有
传入待扫描文件"的预期现象，不影响漏洞库更新。脚本会正常退出。

额外参数直接追加，例如带头 NVD API key：

~~~bash
docker compose --profile cve-db run --rm cve-db-update --nvd-api-key <key>
~~~

两个超时都在 `scan-service/.env` 配置：

| 变量 | 默认 | 含义 |
| --- | --- | --- |
| `CVE_DB_UPDATE_LOCK_TIMEOUT` | 3600 | 等待扫描任务结束的上限（秒）；0 表示不等待，有扫描就直接放弃 |
| `CVE_DB_UPDATE_TIMEOUT` | 3600 | 更新本身的总时长上限（秒）；0 表示不限制 |

定时执行由宿主机负责

注意事项：

- 更新期间扫描会被阻塞等待，等待超时会退出码 3。
- 只更新库时 cve-bin-tool 以退出码 24 结束（见上文），脚本按成功处理；但如果
  此时库文件不存在，脚本仍按失败退出（1）。
- 更新被总超时终止时退出码为 124，库可能处于中间状态，可用 cve-bin-tool
  自带的 `cve-bin-tool-backup` 目录回滚。
- 成功后会在库目录写入 `cve-db.last-updated` 时间戳，便于核对最近一次更新。

## Jenkins 侧

在 Jenkins 上创建 permanent agent `rpm-scan-agent-01`，标签为 `rpm-scan`，
并把其 inbound-agent secret 写入 `scan-service/.env` 的
`RPM_SCAN_AGENT_SECRET`。

Pipeline 参数 `RPM_NAMES` 每行填写一个完整 RPM 文件名，不包含目录；
Pipeline 会先校验并去重，再逐个调用 `run-rpm-scan` 在只读挂载目录
`/scan-input` 下解析文件。
