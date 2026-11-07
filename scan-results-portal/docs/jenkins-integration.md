# Jenkins 接入约定

命令参数与配置分别见 [RPM Agent](../../rpm-scan-agent/README.md#jenkins-接入)、
[SRPM Agent](../../srpm-scan-agent/README.md#jenkins-接入)。

## 接入前准备

- Jenkins 已配置对应的入站 Agent，待扫描包可在 Agent 的 `/scan-input` 中读取。
- 为通知工具绑定 `SCAN_SERVICE_INGEST_TOKEN`，值与门户配置一致；凭据名称可自行约定。
- 使用 Agent 已配置的 `SCAN_RESULTS_PORTAL_URL`，不在 Pipeline 中写死门户地址。
- 门户的 Jenkins 只读账号能访问对应构建和归档产物。

`JOB_NAME`、`BUILD_NUMBER` 使用 Jenkins 提供的值。包名参数只填文件名，不带目录；
RPM 通知中的 `--scan-key`、`--rpm-sha256` 使用待扫描包的同一份 SHA256。

## 扫描、归档与通知

1. 扫描前使用 `send-rpm-event started` 或 `send-srpm-event started` 登记任务。
2. 使用 `run-rpm-scan` 或 `run-srpm-scan` 执行扫描，将每次任务的输出分开存放。
3. 用 Jenkins `archiveArtifacts` 将结果保存到当前构建。
4. 正常结束并完成归档后发送 `completed`；扫描执行失败时发送 `failed`，失败日志也应尽量归档。

归档目录约定：

| 类型 | Jenkins 工作区内的目录 | 需保留的产物 |
| --- | --- | --- |
| SRPM | `srpm-scan-artifacts/<构建号>/` | csmock 生成的完整 `.tar.xz`；额外报告可一并归档 |
| RPM | `rpm-scan-artifacts/<构建号>/<SHA256>/` | `run-rpm-scan` 生成的全部文件，包括清单、JSON、CSV、HTML 和日志 |

Pipeline 负责将输出放入上述目录，不要只保存在工作区，也不要只归档单个展示用报告。
原始结果内容保持不变，由门户检查和解析，无需在 Pipeline 中提取漏洞数量。

`completed` 表示扫描结束，不保证页面立刻显示完成；门户仍需读取和检查归档结果。
通知或归档失败不应被当作扫描工具执行失败。多包遍历、Job 命名和错误汇总策略由调用方决定。

## 异常时怎么办

- **通知发送失败**：先检查地址、Token 和网络，再提供同一门户地址及当前 Token，执行对应的
  `send-rpm-event replay` 或 `send-srpm-event replay` 补发；保留 Agent 工作目录中的 `.scan-event-outbox`。
- **任务已登记但一直未完成**：可能遇到通知遗漏、构建取消或报告读取失败；由维护人员执行
  [主动同步](../README.md#主动同步)。该操作不会导入尚未登记的任务，也不会自动定时执行。
- **结果不可用**：确认产物已归档到当前构建、目录符合约定，且门户账号有读取权限；
  再检查报告是否缺失或损坏。

通知补发只处理已留存的通知，不能补造从未生成的事件。
两类工具都不会要求 Pipeline 预先配置 Job 清单或解析门户返回的任务 ID。
