# Portal 部署入口约定

本文说明当前测试阶段的 HTTP 部署方式，以及进入生产环境后 Scan Results Portal
与公网出口之间的接口边界。

## 当前测试环境

`docker-compose.yml` 将 Portal 容器的 `8080` 端口直接发布到宿主机：

~~~text
http://${PORTAL_BIND_ADDRESS}:${PORTAL_HTTP_PORT}
~~~

示例配置默认是 `0.0.0.0:8081`，便于受控内网中的浏览器和 Jenkins 测试访问。

测试地址示例：

~~~text
http://10.130.43.224:8081/srpm
http://10.130.43.224:8081/rpm
~~~

扫描 agent 与 Portal 位于同一个 Compose 网络，仍使用
`http://scan-results-portal:8080` 上报事件，不经过宿主机端口。

## 生产环境

部署时应执行以下配置：

1. 将 `PORTAL_BIND_ADDRESS` 设置为宿主机私网地址。
2. 仅允许公网出口节点访问 `PORTAL_HTTP_PORT`。
3. 对产物查看和下载关闭响应缓冲，设置合理的长连接超时，并限制单来源请求速率
   与并发连接数。

Portal upstream 的健康检查接口为：

~~~text
GET /readyz
GET /healthz
~~~

## 对外路由边界

只应向匿名用户转发页面、静态资源和只读查询/产物请求（`GET`、`HEAD`）。
以下写接口不得作为公共路由发布：

~~~text
POST /api/v1/rpm/events
POST /api/v1/srpm/events
POST /api/v1/rpm/sync
POST /api/v1/srpm/sync
~~~

其中 event 接口仅供 Compose 私网内的扫描 agent 使用；sync 接口仅供内网调用，
并且 Portal 仍会校验独立的 `SCAN_SERVICE_OPERATOR_TOKEN`。

## 切换检查

接入公网出口后，确认以下条件再停止测试态直连：

- Portal 域名只能通过 HTTPS 访问；
- 外部请求无法访问 event 和 sync 接口；
- Portal 宿主端口仅对公网出口节点和内网开放；
- 页面、在线查看和大文件下载均可用；
- agent 仍可通过 Compose 服务名上报事件。
