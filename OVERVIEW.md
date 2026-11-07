# 扫描服务框架概览

本项目为 Jenkins 提供扫描 Agent、调用工具和结果门户。
Jenkins 与 Pipeline 由使用方维护，负责触发任务、选择 Agent 和组织扫描步骤。

## 各组件做什么

| 组件 | 职责 |
| --- | --- |
| Jenkins | 调度任务，归档并保留原始扫描报告 |
| rpm-scan-agent | 使用 cve-bin-tool 扫描 RPM，提供扫描及通知工具 |
| srpm-scan-agent | 为每次 SRPM 扫描调用一次性 csmock 容器，提供扫描及通知工具 |
| Scan Results Portal | 接收通知，从 Jenkins 读取报告并展示结果，不执行扫描 |
| PostgreSQL | 保存门户的任务索引和结构化结果，不保存完整报告 |

Agent 主动连接外部 Jenkins；门户也需要能够访问 Jenkins 的构建和产物。
扫描组件在 Compose 网络内互相访问，浏览器通过门户查看结果。

## 一次扫描如何完成

1. Jenkins 选择对应 Agent，确定待扫描的输入包。
2. Pipeline 使用通知工具告知门户“扫描开始”，门户建立任务记录。
3. Agent 工具读取输入包、执行扫描，生成的结果由 Pipeline 归档到当前 Jenkins 构建。
4. Pipeline 通知扫描结束；扫描执行失败时通知失败。
5. 门户读取、检查报告后展示结果；用户查看和下载产物时也经由门户访问 Jenkins。

通知成功不等于结果已经就绪；扫描结论与通知、归档是否成功是两回事。
同一套工具可供不同 Job 使用，Pipeline 自行决定包的来源、处理数量及后续步骤，
门户不要求预先列出 Job，也不按 Job 拆分展示页面。

## 数据放在哪里

输入包、漏洞库和 Agent 工作目录由宿主机挂载提供；工作目录也保存待补发通知。
Jenkins 保留归档报告，PostgreSQL 保留门户数据。门户不代替 Jenkins 管理产物保留周期。

目录、权限、配置与工具用法见各组件 README；通知与归档约定见
[Jenkins 接入说明](scan-results-portal/docs/jenkins-integration.md)。
公网接入前需确认[部署入口约定](PORTAL-DEPLOYMENT.md)。
