# OneSocks

将多个代理订阅聚合为一个本地 SOCKS5 服务，通过用户名选择节点，并提供内嵌管理后台和 HTTP API。

直接嵌入 Go 的 `github.com/sagernet/sing-box v1.14.4` 库，HTTP 管理 API 使用 Gin，订阅和节点使用 SQLite 保存，编译为单个程序。不指定配置时，SOCKS5 地址是 `127.0.0.1:1080`，API 地址是 `127.0.0.1:8080`。示例配置使用 `10801` / `10802`，以下命令按示例配置执行。

## 启动

需要 Go 1.25.5 或更新版本。

```bash
go run -tags with_utls ./cmd/onesocks -config configs/config.example.yaml
```

也可以构建后运行：

```bash
make build
./bin/onesocks -config configs/config.example.yaml
./bin/onesocks -version
```

省略 `-config` 使用本地默认参数。`with_utls` 用于支持 Reality/uTLS 相关配置；Hysteria2 已直接注册，无需额外的 `with_quic` 标签。

## 管理后台

按示例配置启动后，打开 <http://127.0.0.1:10802/>；未指定配置时使用 <http://127.0.0.1:8080/>。后台与 API 共用端口，HTML、CSS、JavaScript 直接嵌入 Go 程序，不需要安装前端依赖或单独部署。

后台使用原生前端，视觉参考 Plush UI。修改静态资源后需要重新编译并重启：`make run` 会重新编译后启动；使用可执行文件时先运行 `make build`，再重启 `bin/onesocks`。浏览器刷新会获取新进程提供的资源。

- 订阅：添加、编辑、刷新、删除，查看节点数量和最近刷新结果。编辑时自动回填完整 URL，留空表示保留现有链接。
- 节点：搜索名称、用户名、IP 和地区，组合筛选订阅、协议、国家/地区、检测状态、延迟上限和评分上限，按名称、延迟或评分排序。国家/地区来自 IP 检测结果，未检测或失败的结果不参与数值筛选，排序时放在末尾。
- 分页：默认每页 20 条，可选择 10、20、50、100 条，支持翻页和页码跳转。筛选后回到第一页，节点数量变化时自动校正页码。
- 导出：下载筛选后的全部节点，支持 CSV 表格、SOCKS5 链接 TXT 和完整 JSON；批量检测同样覆盖筛选后的全部节点，不受当前页限制。导出链接使用连接面板中的地址和密码，JSON 保留出站配置和完整检测结果。
- 节点详情：在抽屉中查看连接配置和检测信息，复制 SOCKS5 链接或访问 `ipinfo.io` 的 curl 命令。列表显示出口 IP、国家/地区、延迟和评分。
- 连接信息：填写代理地址和密码、预览后复制。密码从服务配置自动填入并明文显示，页面内修改不影响服务端配置。点击复制直接写入剪贴板，普通 HTTP 页面会自动使用兼容方式。

配置了 `api_token` 时，输入该令牌后访问数据。令牌仅存于当前标签页的 `sessionStorage`，可通过退出清除。未配置令牌时直接进入后台。管理 API 按原值返回订阅 URL、节点出站配置和服务配置，包括密码及令牌。

## 添加订阅和选择节点

```bash
curl -X POST http://127.0.0.1:10802/api/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{"name":"机场A","url":"https://example.com/subscription","refresh_interval":"6h"}'

curl http://127.0.0.1:10802/api/subscriptions
curl http://127.0.0.1:10802/api/nodes
curl http://127.0.0.1:10802/api/status
```

节点列表返回 `username`，以及 `机场A-香港01` 这样的展示名称。用户名与节点 ID 相同，为 `n_` 加 `MD5(subscription_id + 零字节 + 原节点名)` 的完整 32 位小写十六进制值。订阅改名、同名节点配置更新时 ID 不变；原节点改名会改变 ID。同一订阅的同名节点保留最后一条，相同配置但名称不同的节点分别保留。

推荐使用节点 ID 连接；完整展示名称也可作为用户名，但必须唯一且不超过 255 字节。

把下面的 `n_...` 替换为节点列表中的实际用户名：

```bash
curl --proxy socks5h://127.0.0.1:10801 \
  --proxy-user 'n_...:anything' \
  https://example.com
```

默认接受任意非空 SOCKS5 密码。配置 `socks_password` 后，所有节点统一使用该密码；用户名始终负责选择节点。未知用户名或连接失败会返回错误，不自动直连或切换到其他节点。

## 管理 API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/nodes?subscription_id=...` | 节点列表，可按订阅筛选 |
| GET | `/api/subscriptions` | 订阅列表与刷新结果 |
| POST | `/api/subscriptions` | 添加并立即拉取订阅 |
| PATCH | `/api/subscriptions/{id}` | 修改名称、URL、`refresh_interval` |
| POST | `/api/subscriptions/{id}/refresh` | 立即刷新 |
| DELETE | `/api/subscriptions/{id}` | 删除订阅 |
| GET | `/api/status` | 版本、数量、运行及更新状态 |
| GET | `/api/config` | 当前服务配置，包含完整 SOCKS5 密码和 API 令牌 |
| POST | `/api/nodes/{id}/latency` | 通过所选节点探测 HTTP 延迟 |
| POST | `/api/nodes/{id}/ip-check` | 通过所选节点检测出口 IP 与风险信息 |
| POST | `/api/nodes/probe` | 并发检测多个节点，逐项返回 NDJSON 结果 |

创建和修改请求使用 JSON，额外字段会被忽略。创建时省略 `name` 会自动命名，因此也支持只提交 `{"url":"..."}`。`POST /api/subscribe` 与 `DELETE /api/subscribe/{id}` 提供兼容别名。删除和刷新使用订阅列表返回的 `id`。

API 请求体、订阅下载及解析不设额外的字节或节点数量上限。

订阅 URL 可以保留 `#GLaDOS` 等片段标签，服务会自动去掉标签后保存和拉取；仅标签不同的链接视为同一订阅。路径或查询参数中编码为 `%23` 的内容会完整保留。

URL 不做前置格式或协议拦截，直接交给 HTTP 客户端尝试拉取；无法请求时返回 `fetch_failed`，不修改已有节点。

```bash
curl -X POST http://127.0.0.1:10802/api/subscriptions/s_.../refresh
curl -X PATCH http://127.0.0.1:10802/api/subscriptions/s_... \
  -H 'Content-Type: application/json' -d '{"name":"新名称"}'
curl -X DELETE http://127.0.0.1:10802/api/subscriptions/s_...
```

设置 `api_token` 后，所有 API 请求需要添加：

```bash
curl -H 'Authorization: Bearer YOUR_TOKEN' http://127.0.0.1:10802/api/nodes
```

## 节点检测

列表中的「延迟探测」「IP 检测」检测当前筛选的节点，可停止；单个节点在「连接 / 检测」抽屉内操作。检测由后端通过所选节点的 sing-box 出站发起，失败不会改为直连。

- 延迟参考 [Surge URL Test](https://manual.nssurge.com/policy-groups/url-test.html) 的计时方式，测试目标使用 Cloudflare `https://cp.cloudflare.com/generate_204`：发送两次 HEAD，优先记录复用连接后的第二次响应头耗时，排除建连、TLS 和代理握手。不能复用时回退首轮完整耗时并提示。每次独立建连，整次最多 5 秒；收到有效 HTTP 响应头即算连通，不要求 200/204，也不跟随重定向。
- IP 检测向 `https://iplogs.com/v1/check` 发送 `POST {}`，不传 `ip`，由接口识别请求的出口；最多等待 40 秒。抽屉展示检测字段和完整原始响应。
- `score` 是 0–1 的风险证据评分，越高表示代理/VPN特征越明显，不是概率或纯净度。`reputation` 是独立的信誉分类。`confidence` 保留接口原值，官方未公开其计算方法。
- [iplogs](https://iplogs.com/docs.md) 按出口 IP 限制每分钟 60 次请求，每日 2000 次完整检测；超过日额度可能返回 `mode: fast`。限流和上游错误会显示原始详情，不自动重试。
- 最近检测结果保存在 SQLite 的 `nodes.latency_json` 和 `nodes.ip_check_json`，服务重启后恢复。同配置订阅刷新保留结果，节点配置变化或删除时清除。批量检测由后端同时执行当前筛选内全部节点，逐项返回结果，不设并发上限，可停止。

```bash
curl -X POST http://127.0.0.1:10802/api/nodes/n_.../latency
curl -X POST http://127.0.0.1:10802/api/nodes/n_.../ip-check
```

接口返回带 `latency` 或 `ip_check` 的节点信息。节点检测失败时查看结果中的 `error`；节点不存在等 API 错误仍使用原有错误响应。配置了令牌时照常添加 Bearer 认证。

批量接口接收 `{"ids":["节点ID"],"kind":"ip-check"}`，`kind` 也可设为 `latency`。响应为 NDJSON，每行包含 `id` 和 `node` 或 `error`。关闭请求会取消尚未完成的检测。

## 配置与运行行为

配置仅包含 `socks_listen`、`api_listen`、`data_dir`、`socks_password`、`api_token` 和 `outbound_interface`，见 [configs/config.example.yaml](configs/config.example.yaml)。订阅与上次成功的节点保存到 `data_dir/onesocks.db`，重启先恢复缓存，再后台刷新。SQLite 使用纯 Go 驱动 `modernc.org/sqlite`，不需要独立数据库服务。表结构和查询示例见 [数据存储](docs/DATABASE.md)，实际建表来源是 [internal/store/schema.sql](internal/store/schema.sql)。数据库包含订阅 URL 和节点凭据，请勿提交到版本库。

数据库 schema 2 会在启动时自动升级至 schema 3，保留现有订阅、节点和用户名；无需删除数据库。更早的 SQLite 版本不支持。

程序不读写或导入 `state.json`，旧 JSON 文件不会自动删除。管理 API 和 sing-box 出站配置仍使用 JSON。

- 支持多订阅、手动和定时刷新，订阅默认直接通过 HTTP/HTTPS 拉取。默认每 6 小时刷新，可通过订阅 API 的 `refresh_interval` 单独调整。
- 配置忽略未知字段；定时刷新每秒检查一次。
- 节点池与引擎一起切换；刷新、构建或持久化失败时保留旧节点。
- 更新和删除后，已有连接继续使用旧引擎，直到结束或满 5 分钟。
- 订阅 URL、节点 `outbound` 配置和错误详情直接返回原值。
- 监听地址与认证独立配置：`socks_password`、`api_token` 均可留空；API 令牌留空时，可访问该端口的客户端能直接管理订阅。
- 退出时停止服务并关闭连接；更新期间的排空策略不代表进程退出后继续保持连接。

### 与 Mihomo / Clash TUN 共存

TUN 接管系统路由时，可在 OneSocks 配置中指定实际出站网卡，例如：

```yaml
outbound_interface: eth0
```

用 `ip route show default` 查看原网关对应的网卡，将 `eth0` 换成实际名称，保存后重启 OneSocks。此设置让节点连接、节点域名的 DNS 请求及订阅下载（包括其 DNS）绑定该接口；接口留空时沿用系统路由。接口绑定失败会返回错误，不回退到系统路由。Linux 通常需要相应的网络权限。

绑定只在引擎中应用，不修改订阅节点配置或节点 ID。`curl --interface eth0` 只控制 curl 自己到本地 SOCKS5 的连接，代理服务器的出站接口由本配置控制。如果 DNS 指向 Mihomo 的本地 Fake-IP 服务，仍需改用可从该接口访问的真实 DNS，或在 Mihomo 中排除节点域名。

## 当前兼容范围

支持 sing-box JSON 的代理出站、明文节点 URI 列表和整包 Base64。协议包括 SS、VLESS、Trojan、VMess、Hysteria2、AnyTLS，覆盖常用 TCP/TLS、Reality、WS、gRPC 配置；具体协议与传输组合并非全覆盖。

SS 支持 sing-box 内置的 `obfs-local`（HTTP/TLS）和 WebSocket 模式的 `v2ray-plugin`，插件参数完整保留。订阅中的 `domain_resolver` 引用会替换为 OneSocks 的 `bootstrap`，保留对象形式的解析策略与超时参数，并在响应中报告 warning；订阅自己的 DNS 服务、路由和监听配置不导入。

URI 中已识别的参数会转换为 sing-box 字段，额外参数会被忽略。JSON 节点的协议、插件和扩展选项由 sing-box 在构建引擎时处理；不兼容配置导致更新失败，保留旧节点池。

不支持的协议条目报告为 warning；全部无效时更新失败，保留旧池并返回具体解析原因。任意链式出站以及第三方完整路由配置不导入。

本地 SOCKS5 目前仅支持 **TCP CONNECT**，不支持 UDP ASSOCIATE、BIND。不自动执行后台探测，手动检测结果见 `latency` 和 `ip_check` 字段。

## 验证

```bash
make test
make race
```

测试包含本地受控 sing-box 服务端的 SS、VLESS、VMess、Trojan TLS、Hysteria2 TLS、AnyTLS 协议往返，VLESS/VMess/Trojan 的 WS/gRPC 组合，以及 API → SOCKS5 → SS 的完整链路。另覆盖解析、认证、状态恢复、更新回退和旧连接保留。`obfs-local` 已验证配置构建；Reality 已验证配置构建，尚未做完整服务端握手验证。

模块划分与运行流程见 [架构说明](docs/PLAN.md)。
