# 页面显示时区

Portal 的 `config/config.yaml` 中，`ui.timezone` 控制 SRPM、RPM 一级和二级页面的
Created、Finished 显示时区，默认 `Asia/Shanghai`。接受 IANA 时区名，例如 `UTC`；
无效配置会在启动时报告 `ui.timezone` 错误。配置由进程缓存，修改后需重启 Portal。

两类页面共用 `scanservice/time_display.py`，先通过 ZoneInfo 转换时间点，
再按 `YYYY-MM-DD HH:MM:SS` 输出。空时间继续显示 `—`，不显示小数或时区后缀。

转换仅发生在展示层，不重写数据库时间，也不改变查询 API 的 ISO-8601 时间格式。
现有数据库记录无需迁移。带时区的值按其真实时间点转换；不带时区的内部时间
明确按 UTC 解释，不使用容器的本地时区。

Agent 的 `/etc/localtime` 设置可继续保留，便于查看工具日志，但不负责控制网页显示。
事件时间仍须携带时区，不应手动加 8 小时。此公共逻辑仅供 Portal 使用，
无需让 Agent 安装或依赖 Portal 的展示代码。
