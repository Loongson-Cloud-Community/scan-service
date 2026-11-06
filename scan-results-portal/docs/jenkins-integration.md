# Jenkins 接入约定

本文档描述 Jenkins Pipeline 与 Scan Results Portal（下称门户）之间的对接
约定，SRPM 与 RPM 两种扫描都适用。

## 一、前置条件

门户不向 Jenkins 推送任何数据，Pipeline 需要做两件事：

1. **发事件**：扫描开始/结束/失败时调用门户的事件接口；
2. **归档产物**：用 `archiveArtifacts` 把扫描结果归档到本构建；门户随后
   自己通过 Jenkins API 把产物读回去解析。

因此需要满足：

- Jenkins 侧存在凭据 `scan-service-ingest-token`（Secret text），值与门户的
  `SCAN_SERVICE_INGEST_TOKEN` 一致；
- 门户侧配置了 `JENKINS_BASE_URL`、`JENKINS_USER`、`JENKINS_TOKEN`
  （只读权限即可），且门户可以访问 Jenkins 的 API 与 artifact；
- Pipeline 所在的 agent 能访问门户：地址由 agent 容器的环境变量
  `SCAN_RESULTS_PORTAL_URL` 提供（栈内为 `http://scan-results-portal:8080`），
  **不要写死在 Pipeline 里**；
- 产物必须通过 `archiveArtifacts` 归档到本构建，门户只读取 Build 的
  artifacts。

## 二、认证

事件接口使用 Bearer Token：

```text
Authorization: Bearer <SCAN_SERVICE_INGEST_TOKEN>
```

Pipeline 里用 `credentials('scan-service-ingest-token')` 取值。

## 三、事件接口

| 扫描类型 | 接口 |
| --- | --- |
| SRPM | `POST /api/v1/srpm/events` |
| RPM | `POST /api/v1/rpm/events` |

事件有 `started` / `completed` / `failed` 三种。任务由
`jenkins_job_full_name + jenkins_build_number`（RPM 还包含 `scan_key`）唯一
确定；新 Pipeline 不需要预先创建任务或解析任务 ID，同一构建重复发送
`started` 也不会重复建任务。

事件字段采用严格类型校验：构建号是正整数，不接受布尔值、小数或数字字符串；
Job 名不得包含空路径段、`.`、`..` 或控制字符。文件名只能是文件名本身，不能带目录。
提供时间时须使用带时区的 ISO-8601 字符串，退出码须为整数。
格式错误返回 HTTP 422；同一任务上报的包名或校验和与已登记信息冲突时返回
HTTP 409，不修改原任务。

### 3.1 SRPM 事件字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `event` | 是 | `started` / `completed` / `failed` |
| `jenkins_job_full_name` | 是 | 完整 Job 名，支持 `packages/curl` 这类 folder 路径 |
| `jenkins_build_number` | 是 | 构建号 |
| `srpm_name` | 否 | 完整 SRPM 文件名，建议发送；页面的 Label 用它，扫描失败或结果包缺失时页面仍能显示包名 |
| `created_at` | started 用 | ISO-8601 扫描开始时间 |
| `finished_at` | completed/failed 用 | ISO-8601 扫描结束时间 |
| `csmock_exit_code` | 否 | csmock 退出码 |

开始扫描：

```json
{
  "event": "started",
  "jenkins_job_full_name": "packages/curl",
  "jenkins_build_number": 15,
  "srpm_name": "curl-8.4.0-9.ocs23.src.rpm",
  "created_at": "2026-09-24T10:00:00+08:00"
}
```

扫描失败：

```json
{
  "event": "failed",
  "jenkins_job_full_name": "packages/curl",
  "jenkins_build_number": 15,
  "srpm_name": "curl-8.4.0-9.ocs23.src.rpm",
  "finished_at": "2026-09-24T10:02:00+08:00",
  "csmock_exit_code": 2
}
```

### 3.2 RPM 事件字段

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `event` | 是 | `started` / `completed` / `failed` |
| `scan_key` | 是 | 必须等于 `rpm_sha256`；门户按它定位归档目录 |
| `jenkins_job_full_name` | 是 | 完整 Job 名 |
| `jenkins_build_number` | 是 | 构建号 |
| `rpm_name` | 是 | RPM 文件名 |
| `rpm_sha256` | 是 | RPM 的 sha256（64 位小写十六进制） |
| `created_at` | started 用 | ISO-8601 扫描开始时间 |
| `finished_at` | completed/failed 用 | ISO-8601 扫描结束时间 |
| `cbt_exit_code` | 否 | cve-bin-tool 退出码 |

开始扫描：

```json
{
  "event": "started",
  "scan_key": "<RPM 的 sha256>",
  "jenkins_job_full_name": "rpm-docker-test",
  "jenkins_build_number": 1,
  "rpm_name": "docker-24.0.9-8.lns23.loongarch64.rpm",
  "rpm_sha256": "<RPM 的 sha256>",
  "created_at": "2026-09-24T10:00:00+08:00"
}
```

### 3.3 事件时序

- 扫描阶段开始前发 `started`（门户据此建任务，状态 `RUNNING`）；
- 扫描正常结束、且已完成归档后发 `completed`；
- 扫描阶段失败发 `failed`，不要发 `completed`。

`completed` 的 HTTP 200 表示结束时间、退出码等事件信息已经落库，
不表示结果已解析成功。门户在响应发送后使用独立数据库会话读取 Jenkins
产物并校验，响应中的状态可能仍为 `RUNNING`、`sync_status=PENDING`；
最终状态以之后查询任务得到的结果为准。重复通知仍遵循终态保护。

后台步骤不是持久化队列。如果门户进程在确认事件后中断，或 Jenkins 暂时不可用，
已登记任务不会丢失，可通过现有的授权补偿同步接口重试；目前没有自动轮询恢复。
这一处理不要求 Agent 或调用方增加环境变量，也不改变事件字段及认证方式。

### 3.4 通知失败后的恢复

两个 Agent 的事件工具在发送前将原始事件提交到本地 SQLite outbox，收到成功响应且
JSON 中含有效任务 ID 后才删除；HTTP 200 的代理错误页不算确认。
位置为 `JENKINS_AGENT_WORKDIR/.scan-event-outbox/rpm.sqlite3` 或
`srpm.sqlite3`，默认位于已挂载的 `/home/jenkins/agent` 内，不依赖单次构建目录。
恢复目录和数据库权限分别为 0700、0600；只保存目标接口和事件内容，不保存 Token。
工作目录挂载必须保留；删除它也会删除未交付事件。

短暂故障仍做有限重试；重试耗尽、明确 HTTP 拒绝或进程中断时，事件留存，不伪装成
扫描失败，也不把发送失败改成成功退出。网络或配置恢复后，可在对应 Agent 内、
按现有方式提供 `SCAN_SERVICE_INGEST_TOKEN`，执行：

```text
send-rpm-event replay
send-srpm-event replay
```

重发不需要当前 Job、Build 或包名参数，使用原始事件内容和时间、当前 Token。
每次最多处理 20 条，输出已交付和剩余数量，反复执行可继续处理；拒绝项仍保留，
不会阻止同批其他事件，也不会一直占据后续批次。切换门户地址后，不会将旧目标的
事件转发到新目标。Portal 已接收但响应丢失时可能重复交付，由现有幂等规则保护。

这只是独立的恢复工具，不新增后台常驻任务，也不要求修改外部 Pipeline。
即使任务尚未在 Portal 登记，也能先重发开始事件恢复登记；Portal 的同步接口仍只
负责已登记任务的结果补偿。明确的 401/409/422 等拒绝需先排查，原样重发不保证成功。

## 四、产物归档要求

`completed` 只表示扫描与归档阶段已经结束，不代表扫描成功；门户会重新读取
Build 的 artifacts 并自行校验。

### 4.1 SRPM

门户只处理位于 `srpm-scan-artifacts/` 前缀下的 artifacts，并从中挑选第一个
满足条件的 `.tar.xz` 作为扫描结果，条件是：

- 归档内**必须包含**以下 6 个文件：

```text
scan.ini
scan-results-summary.txt
scan-results.js
scan-results.err
scan-results.html
scan.log
```

- 结构：这些文件必须来自同一个目录、各出现一次，要么位于归档根目录，要么位于 `<NVR>/` 下一层；
  `<NVR>/debug/` 下的内容会被忽略；
- 归档必须能正常解压，单个归档默认不超过 128 MiB（可通过产物预算配置调整）；
- `scan.ini` 的 `[scan]` 必须标明 `tool = csmock`，`project-name` 须与登记的
  SRPM 文件名去掉 `.src.rpm` / `.nosrc.rpm` 后一致；
- 正常结束的退出码须可由扫描元数据或回调确定；非零退出码标为
  `FAILED`，不能被可选元数据中的成功退出码覆盖；
- 摘要允许为空，表示没有发现问题；除空行和注释外，每一行必须能够解析，
  无法识别或损坏的内容不能作为“0 findings”的成功结果；
- 可选：额外归档 `.sarif` 文件，门户会据此解析 finding 明细；
- 可选：归档 `scan-manifest.json` 作为任务元数据（字段为扁平结构）。
  门户会读取其中的 `package_name`、`version`、`release`、`nvr`、
  `srpm_name`、`architecture`、`source_revision`、`source_url`、
  `source_sha256`、`scanner`、`scanner_version`、`mock_config`、
  `csmock_exit_code`、`gate_result`、`plugins`（或 `enabled_plugins`）。
  其中 `scanner` 可以是 `csmock` 字符串，或包含 `name = csmock`、`version` 的对象。
  整份元数据先校验字段类型、长度及任务身份，不能改写已登记的包名；
  如果提供 `schema_version`，目前仅支持整数 `1`。
  可选元数据无效时整份忽略，并在任务元数据中记录 `manifest_error`；
  不影响有效主结果的接受。

### 4.2 RPM

门户只读取位于
`rpm-scan-artifacts/<build_number>/<scan_key>/` 前缀下的这些文件：

```text
scan-manifest.json
scan-results.json
scan-results.csv
scan-results.html
scan.log
```

其中 `scan-manifest.json` 与 `scan-results.json` 是必需的。manifest 的
`schema_version` 必须为整数 `1`、`scan_type` 必须为 `rpm`；
`rpm.sha256` 必须与事件里的 `scan_key` / `rpm_sha256` 一致，`rpm.filename`
必须与已登记包名一致，且 `scanner.name` 必须是 `cve-bin-tool`。
`scanner.exit_code` 必须为整数，不能以布尔值或字符串代替；`scanner.args`
如果提供，必须为字符串数组。若 manifest 额外提供 Job、Build 或 `scan_key`，
也必须与已登记任务一致。单个解析文件默认不超过 16 MiB。

## 五、状态判定

两种扫描共用四种状态，但判定条件不同：

| 状态 | SRPM | RPM |
| --- | --- | --- |
| `RUNNING` | 已收到 `started`，尚未结束 | 同左 |
| `FINISHED` | csmock 正常结束且归档内容校验通过 | 两个 json 校验通过，扫描器退出码为 0 或 1 |
| `FAILED` | 收到 `failed` 或确认 csmock 非零退出 | 收到 `failed` 或确认扫描器退出码不为 0/1 |
| `NOT_AVAILABLE` | 扫描已结束，但结果包缺失、损坏、无法解压或缺少预期文件 | 扫描已结束，但缺少有效的 manifest/json |

RPM 的 `cbt_exit_code` 为 1 表示扫描成功且发现漏洞，只有大于 1 才是失败。

## 六、只读与同步接口（可选）

| 用途 | 接口 |
| --- | --- |
| 任务列表 / 详情 | `GET /api/v1/{srpm\|rpm}/tasks`、`GET /api/v1/{srpm\|rpm}/tasks/{id}` |
| 内部运维补偿同步（需 operator Token） | `POST /api/v1/{srpm\|rpm}/sync` |

Pipeline 不需要调用同步接口，它用于内部运维补偿与排查，不会由公开页面自动触发。
`sync` 的行为：重新读取门户中已登记且尚未进入终态（`RUNNING` /
`NOT_AVAILABLE`）的任务，逐个回 Jenkins 重新同步，最多处理
`RECENT_BUILD_LIMIT` 个。优先选择最久未尝试的任务；从未尝试过的使用门户
登记时间排序，同一时间按任务 ID 升序。成功和失败的尝试都会推进轮次，
不会总被新任务占满批次；不会导入没有登记过的构建。

同步响应中的计数均指本次补偿批次：

| 字段 | 含义 |
| --- | --- |
| `attempted` | 已尝试处理的任务数，等于下面三类之和 |
| `synced` | 已同步到明确终态，且 `sync_status=SYNCED` 的任务数 |
| `pending` | 已处理但仍待完成或待确认的任务数 |
| `failed` | 结果不可用（`sync_status=ERROR`）或本次同步抛出异常的任务数 |

`failed` 是同步失败，不是扫描状态 `FAILED`。扫描器执行失败但结论已可靠同步时，
仍计入 `synced`；缺少有效产物不能因为同步函数正常返回就计为成功。

## 七、多包、多 Job 接入

多个包的 Job 可以共用同一套 Pipeline 模板。事件接口不要求 Job 预先登记，
只要事件里的 `jenkins_job_full_name` 是完整 Job 名即可；页面按扫描时间统一
显示，不按 Job 分组。

门户不维护 Job 白名单：任务只通过事件或已登记任务的重新同步产生。

## 八、常见问题

- 事件返回 401：Bearer Token 与门户的 `SCAN_SERVICE_INGEST_TOKEN` 不一致；
- 事件返回 422：`event` 取值非法，或缺少必填字段；
- 任务一直是 `RUNNING`：可能只发了 `started`，也可能完成事件已落库但后台同步未完成；
  检查 `finished_at`、`sync_status` 与门户日志，必要时执行授权补偿同步；
- 任务为 `NOT_AVAILABLE`：产物没有归档、归档损坏，或缺少预期文件；
- 任务为 `FAILED`：扫描阶段本身失败（SRPM 收到 `failed`；RPM 退出码大于 1）；
- 归档已上传但门户读不到：确认产物是通过 `archiveArtifacts` 归档到本构建，
  且 RPM 的产物位于
  `rpm-scan-artifacts/<build_number>/<scan_key>/` 前缀下。
