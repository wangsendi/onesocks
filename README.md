# OneSocks

OneSocks 将多个代理订阅聚合为一个 SOCKS5 服务，通过用户名选择出站节点。程序使用 Go 编写，基于 [things-go/go-socks5](https://github.com/things-go/go-socks5) 提供 SOCKS5 接入，内嵌 sing-box 协议引擎、Gin 管理 API 和 Web 管理界面，使用 SQLite 保存订阅、节点及检测结果。

## 功能

- 订阅管理：添加、编辑、删除、手动刷新和定时刷新多个订阅。
- 节点选路：通过同一 SOCKS5 端口访问不同节点，使用节点 ID 或完整名称作为用户名。
- 流量转发：支持 TCP 和 SOCKS5 UDP，可承载 QUIC / HTTP/3 流量。
- 节点检测：检测 HTTP 延迟、出口 IP、国家/地区及 IP 风险评分，支持并发批量检测。
- 节点管理：搜索、组合筛选、排序、分页，导出 CSV、SOCKS5 链接和 JSON。
- 单文件部署：管理界面随程序编译，无需独立前端服务或数据库服务。

## 快速开始

构建需要 Go 1.25.5 或更新版本。

在项目根目录创建 `config.yaml`：

```yaml
socks_listen: 127.0.0.1:10801
api_listen: 127.0.0.1:10802
data_dir: data
socks_password: ""
api_token: ""
outbound_interface: ""
```

构建并启动：

```bash
make build
./bin/onesocks -config config.yaml
```

也可以直接运行源码：

```bash
go run -tags with_utls ./cmd/onesocks -config config.yaml
```

启动后访问 <http://127.0.0.1:10802/>，在管理界面添加订阅。以下示例均使用上述端口。

### 添加订阅

```bash
curl -X POST http://127.0.0.1:10802/api/subscriptions \
  -H 'Content-Type: application/json' \
  -d '{"name":"机场A","url":"https://example.com/subscription","refresh_interval":"6h"}'
```

`refresh_interval` 可省略，默认每 6 小时刷新。订阅 URL 中的 `#` 片段标签会在保存和请求前移除。

### 使用代理

获取节点列表：

```bash
curl http://127.0.0.1:10802/api/nodes
```

将 `NODE_USERNAME` 替换为响应中 `items[].username` 的值：

```bash
curl --proxy socks5h://127.0.0.1:10801 \
  --proxy-user 'NODE_USERNAME:anything' \
  --max-time 30 \
  https://ipinfo.io/json
```

未设置 `socks_password` 时，密码可为任意非空字符串；设置后需使用配置中的密码。管理界面可直接复制 SOCKS5 链接和 curl 命令。

用户名与节点 ID 相同，格式为 `n_` 加 `MD5(subscription_id + "\x00" + 原节点名)`。订阅改名或节点配置更新不会改变 ID；原节点改名会生成新的 ID。同一订阅中名称相同的节点保留最后一条。

完整展示名称（如 `机场A-香港01`）也可作为用户名，但需唯一且不超过 255 字节。

## 配置

通过 `-config` 指定 YAML 配置文件。省略该参数时使用下表默认值；相对路径以程序工作目录为基准。

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `socks_listen` | `127.0.0.1:1080` | SOCKS5 监听地址 |
| `api_listen` | `127.0.0.1:8080` | 管理界面及 API 监听地址 |
| `data_dir` | `data` | SQLite 数据目录 |
| `socks_password` | 空 | 所有节点共用的 SOCKS5 密码；留空接受任意非空密码 |
| `api_token` | 空 | API Bearer 令牌；留空关闭 API 鉴权 |
| `outbound_interface` | 空 | 出站网卡；留空使用系统路由 |
| `probe_concurrency` | `16` | 节点检测总并发上限，必须为正整数；单节点与所有批量请求共享 |

设置 `api_token` 后，管理界面需要输入令牌，API 请求需要携带认证头：

```bash
curl -H 'Authorization: Bearer YOUR_TOKEN' \
  http://127.0.0.1:10802/api/nodes
```

管理界面和 API 返回完整订阅 URL、节点配置及服务配置，不进行脱敏。

### 出站网卡

与 Mihomo 等 TUN 客户端共存时，可将 `outbound_interface` 设置为实际物理网卡，例如 `eth0`。此配置用于绑定节点连接、节点域名解析和订阅下载的出站接口，修改后需重启程序。

接口绑定取决于系统权限和路由配置。若系统 DNS 指向 TUN 客户端的 Fake-IP 服务，还需调整 DNS 或为节点域名配置排除规则。

## 管理界面

节点列表按节点、出口 IP / 地区、延迟、风险评分和操作分列，小屏幕下显示为紧凑列表。支持按订阅、协议、国家/地区、检测状态、延迟上限和评分上限组合筛选，并按名称、延迟或评分排序。可搜索节点名称、用户名、IP 和地区；每页显示 10、20、50 或 100 条，支持点击页码，超过 5 页时可输入页码跳转。

导出和批量检测作用于筛选后的全部节点，包含其他分页中的结果。导出支持 CSV 表格、SOCKS5 链接 TXT 和完整 JSON；链接使用连接设置中的地址和密码。点击“连接”打开连接配置，点击“详情”查看检测结果，关闭后焦点回到原按钮；列表不保留选中状态。

### 节点检测

- **HTTP 延迟**：通过所选节点向 Cloudflare 发送 HEAD 请求，优先记录复用连接后的第二次响应耗时；无法复用时记录首次请求的完整耗时。
- **IP 检测**：通过所选节点向 [iplogs](https://iplogs.com/) 发送请求，由其识别出口 IP，返回位置、网络归属和风险信息。`score` 范围为 0–1，数值越高表示风险证据越强。

检测结果自动保存至 SQLite，重启后恢复。节点出站配置发生变化时清除旧结果。节点检测默认最多同时运行 16 项，单节点与多个批量请求共享 `probe_concurrency` 额度，超出部分排队。每完成一项就显示结果，单项失败不影响其他节点。

## HTTP API

请求和响应使用 JSON，批量检测响应使用 NDJSON。订阅和节点列表通过 `items` 字段返回。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/subscriptions` | 获取订阅列表及刷新状态 |
| POST | `/api/subscriptions` | 添加并立即拉取订阅 |
| PATCH | `/api/subscriptions/{id}` | 修改 `name`、`url` 或 `refresh_interval` |
| POST | `/api/subscriptions/{id}/refresh` | 刷新订阅 |
| DELETE | `/api/subscriptions/{id}` | 删除订阅及其节点 |
| GET | `/api/nodes` | 获取节点列表，可通过 `subscription_id` 查询参数筛选 |
| POST | `/api/nodes/{id}/latency` | 检测单个节点的 HTTP 延迟 |
| POST | `/api/nodes/{id}/ip-check` | 检测单个节点的出口 IP |
| POST | `/api/nodes/probe` | 并发批量检测节点 |
| GET | `/api/status` | 获取版本、运行状态及订阅和节点数量 |
| GET | `/api/config` | 获取当前服务配置 |

批量检测示例，将 `NODE_ID` 替换为实际节点 ID，`kind` 可选 `latency` 或 `ip-check`：

```bash
curl -N -X POST http://127.0.0.1:10802/api/nodes/probe \
  -H 'Content-Type: application/json' \
  -d '{"ids":["NODE_ID"],"kind":"latency"}'
```

响应按完成顺序逐行包含 `id` 及 `node` 或 `error`。单个节点的检测失败原因保存在 `node.latency.error` 或 `node.ip_check.error` 中。关闭批量请求或停止检测会取消正在运行的任务，并丢弃尚未开始的队列；未开始的节点不会更新检测结果。

批量流式请求不受普通 API 的 3 分钟总时限限制；每项延迟检测最多 5 秒、IP 检测最多 40 秒，每次响应写入最多等待 30 秒。修改并发配置后需要重启服务。

## 数据存储

数据库位于 `data_dir/onesocks.db`，默认路径为 `data/onesocks.db`。程序启动时恢复已保存的节点，并在后台刷新订阅；刷新失败时保留上次成功的节点。

| 表 | 内容 |
| --- | --- |
| `subscriptions` | 订阅名称、URL、刷新间隔及最近刷新状态 |
| `nodes` | 节点名称、所属订阅、sing-box 出站配置及延迟和 IP 检测结果 |
| `app_state` | 当前节点池版本 |

节点使用 `(subscription_id, name)` 唯一约束，删除订阅时级联删除节点。完整表结构见 [schema.sql](internal/store/schema.sql)。`data/`、本地 `config.yaml` 和构建产物均已加入 Git 忽略规则。

## 支持范围

订阅支持 sing-box JSON、节点 URI 列表及 Base64 编码的 URI 列表。支持的协议包括 Shadowsocks、VLESS、Trojan、VMess、Hysteria2 和 AnyTLS，以及常用的 TLS、Reality、WebSocket 和 gRPC 配置。

仅导入独立代理出站，不导入订阅的监听、路由或完整 DNS 配置，不支持 Clash YAML 和链式出站。本地 SOCKS5 支持 TCP CONNECT 和 UDP ASSOCIATE，不支持 BIND。

UDP 与 TCP 由同一个 OneSocks 进程处理。客户端先通过 TCP 认证并协商 UDP 会话，再向返回的 UDP 地址发送带有 SOCKS5 目标地址头的数据包。TCP 控制连接只维持会话，UDP 数据不经过这条 TCP 连接转发。当前每个会话分配一个临时 UDP 中继端口；远程、容器或 NAT 部署时，需要保证返回的地址和 UDP 端口可从客户端访问。

客户端和所选节点均需支持 UDP，才能转发 QUIC / HTTP/3；仅支持 SOCKS5 TCP 的客户端不会自动获得此能力。发往订阅节点的外层封装由节点协议决定。现有 HTTP 延迟及 IP 检测仍使用 TCP，不能据此判断节点的 UDP 可用性。

UDP 会话在 TCP 控制连接关闭或空闲 2 分钟后清理，每个目标的空闲连接也会独立回收。每个会话最多保留 128 个目标，每个目标最多排队 8 个数据包；超出限制的包及 SOCKS5 分片包会被丢弃。

## 构建与测试

```bash
make build   # 构建 bin/onesocks
make test    # 运行测试
make race    # 运行竞态检测
```

默认构建标签为 `with_utls`，用于支持 uTLS 和 Reality。静态资源通过 `go:embed` 内嵌，修改管理界面后需重新构建并重启程序。

## 许可证

见 [LICENSE](LICENSE)。
