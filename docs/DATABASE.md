# 数据存储

程序通过 `database/sql` 和纯 Go 驱动 `modernc.org/sqlite` 保存状态，数据库文件为 `data_dir/onesocks.db`。静态监听地址、API token、SOCKS5 密码和出站网卡仍在 YAML 配置中。

新库通过嵌入的 [internal/store/schema.sql](../internal/store/schema.sql) 建表。数据库结构版本为 `PRAGMA user_version = 3`。

现有 schema 2 在启动时自动增加两个检测结果字段，升级至 schema 3，保留订阅和节点。无需删除数据库或重新添加订阅。更早的 SQLite 版本不支持。

程序不读取、写入或导入 `state.json`，已有 JSON 文件不会自动删除。新数据库首次启动为空。HTTP API 和保存的 sing-box 出站对象仍使用 JSON。

## 表结构

| 表 | 字段 | 说明 |
| --- | --- | --- |
| `app_state` | `id` | 固定为 `1` 的状态行 |
| `app_state` | `generation` | 成功提交的节点池版本 |
| `subscriptions` | `id` | 订阅主键，修改名称或 URL 时保留 |
| `subscriptions` | `name` | 订阅名称，唯一 |
| `subscriptions` | `url` | 去除 fragment 标签后的订阅 URL，唯一 |
| `subscriptions` | `refresh_interval` | 刷新间隔，如 `6h` |
| `subscriptions` | `last_attempt_at`, `last_success_at` | UTC RFC3339 时间，尚未发生时为 `NULL` |
| `subscriptions` | `last_error` | 最近失败原因，无错误时为空字符串 |
| `nodes` | `id` | 节点主键，同时作为 SOCKS5 用户名 |
| `nodes` | `subscription_id` | 关联订阅，删除订阅时级联删除 |
| `nodes` | `name` | 原节点名称 |
| `nodes` | `outbound_json` | 解析后的 sing-box 出站对象，包含协议、服务器、凭据和传输配置 |
| `nodes` | `latency_json` | 最近一次延迟结果：检测时间、毫秒数、连接复用状态、警告或错误；未检测为 `NULL` |
| `nodes` | `ip_check_json` | 最近一次 IP 检测：检测时间、完整 iplogs 响应或错误；未检测为 `NULL` |

`nodes.id` 为 `n_` 加 `MD5(subscription_id + 零字节 + 原节点名)` 的完整 32 位小写十六进制值；表中还设有 `UNIQUE(subscription_id, name)`。同一订阅的同名条目最后一条覆盖，相同配置但名称不同的条目是不同节点。加载时按节点名称排序，不保留订阅原始顺序。

订阅改名、同名节点配置更新不改变节点 ID；原节点改名会改变 ID。完整展示名称 `订阅名-原节点名` 继续作为唯一匹配时可用的别名。

以下公开字段在运行时计算，不重复保存：

| 字段 | 来源 |
| --- | --- |
| 节点 `username` | 与 `nodes.id` 相同 |
| 节点 `protocol` | 出站 JSON 的 `type` |
| 节点展示名称 | 订阅名称与原节点名称 |
| 订阅 `node_count` | 按原节点名保留的节点数 |
| 订阅 `stale` | `last_error` 是否非空 |
| 节点 `health` | 当前统一为 `unknown` |

## 事务与连接

新增、修改和刷新先在事务外构建候选节点池与 sing-box 引擎，再在事务中写入目标订阅、更新或插入节点、删除已消失的节点，并增加 `generation`。事务成功后才发布候选运行实例；失败则回滚并关闭候选引擎，保留原实例。

检测结束后先写入 SQLite，再发布结果。延迟与 IP 结果独立更新，成功和失败均保留，服务重启时恢复。订阅刷新或改名不会清除配置未变的节点结果；节点出站配置变化时清空结果，删除节点时一并删除。配置 JSON 的键顺序和空白变化不影响判断。检测期间节点被修改或删除时，不保存过期结果。写库失败会返回 `storage_failed`，保留上次结果。

删除订阅、级联删除节点和增加 `generation` 使用同一事务。刷新失败通过独立 UPDATE 保存 `last_attempt_at` 和 `last_error`，保留成功时间、节点及版本。

应用使用单连接池，每次建立连接时通过 DSN 配置 `journal_mode = WAL`、`foreign_keys = ON`、`busy_timeout = 5000` 和 `synchronous = FULL`。SOCKS5 选路和转发使用内存节点池，每条连接无需查询数据库。

## 查看数据

可使用 SQLite 命令行查看数据库：

```bash
sqlite3 data/onesocks.db
```

```sql
PRAGMA user_version;
PRAGMA journal_mode;

SELECT generation FROM app_state WHERE id = 1;

SELECT id, name, refresh_interval, last_success_at, last_error
FROM subscriptions
ORDER BY name;

SELECT subscription_id, COUNT(*) AS node_count
FROM nodes
GROUP BY subscription_id;

SELECT id, subscription_id, name,
       json_extract(outbound_json, '$.type') AS protocol
FROM nodes
ORDER BY subscription_id, name
LIMIT 20;

SELECT name,
       json_extract(latency_json, '$.milliseconds') AS latency_ms,
       json_extract(ip_check_json, '$.data.ip_info.ip') AS exit_ip,
       json_extract(ip_check_json, '$.data.ip_info.country') AS country,
       json_extract(ip_check_json, '$.data.score') AS score,
       json_extract(ip_check_json, '$.checked_at') AS ip_checked_at
FROM nodes;
```

数据库及 WAL 文件包含订阅令牌和节点凭据，属于本地运行数据。
