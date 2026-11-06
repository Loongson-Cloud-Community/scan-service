# 扫描明细分页

## RPM 详情页面

`/rpm/{id}` 的 Components 和 Vulnerabilities 独立分页，分别使用
`component_page`、`vulnerability_page` 参数，默认均为第 1 页。
每页数量沿用 `ui.page_size`，有效范围为 1～200；超过范围的配置在详情页收敛到边界。
翻页保留另一张表的页码，跳转后定位到 Results。

页面顶部的 unique CVEs 与危险等级汇总仍是整个任务的统计，不受分页影响。
分页中的 total 是对应表的明细记录数，不等于去重 CVE 数：同一 CVE
可能对应多个组件版本，因此可能有多条漏洞记录。
Details、Logs、证据展开方式和一级任务列表保持不变。

## SRPM findings 接口

`GET /api/v1/srpm/tasks/{id}/findings?page=1&page_size=50`

与任务列表接口一致，返回分页对象：

```json
{
  "page": 1,
  "page_size": 50,
  "total": 213,
  "items": []
}
```

示例中的 items 省略具体明细。**此接口不再返回顶层数组**；外部调用方需要
从 `items` 读取原有明细，并按 `total` 继续获取后续页。
每条明细的字段不变，包括 `raw` 和 `code_context`。
`total` 为实际 finding 记录数，不取自可能包含不同统计口径的 summary。

`page` 从 1 开始，`page_size` 默认 50，最大 200；非法参数返回 422。
不存在的任务返回 404，超出末页时返回空 items，保留 total。
finding 按 ID 升序，RPM 明细沿用原来的排序字段并用 ID 确保同值记录顺序稳定。
分页针对当前数据；结果重新同步期间，不保证多次请求拥有同一数据库快照。
SRPM summary 接口和页面不受影响。
