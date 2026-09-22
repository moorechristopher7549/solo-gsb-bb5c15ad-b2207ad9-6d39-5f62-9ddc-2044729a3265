# Capability Token API

基于 **Python / FastAPI / SQLite** 的能力令牌（Capability Token）服务，为文件下载等
HTTP 操作签发**短期 HMAC 签名令牌**，并在使用时进行严格验证。无需任何第三方账号或外部
依赖（不需要 Redis、JWT 服务、对象存储账号等），单个 SQLite 文件即完整运行。

- 🔐 **HMAC-SHA256 签名**，令牌自包含、可离线验证（多用途令牌无状态）
- 🔑 **无中断密钥轮换**：`CAPABILITY_KEYRING` 是有序的 `kid:secret` 列表，首项签发、
  按 `kid` 精确选键验签；保留旧 kid 即可继续验证未过期旧令牌，移除即立即拒绝，
  并兼容无 `kid` 的旧令牌（仅用 `CAPABILITY_LEGACY_SECRET`，绝不遍历试签）
- 🔗 **绑定 HTTP 方法与规范化路径**：令牌不能被挪用到其它动词或路径
- ⏱️ **短期有效**：签发时指定 TTL，服务端强制上限，过期即失效
- 🔁 **可选一次性 nonce**：成功使用后原子写入 SQLite，重放请求被拒绝
  （`BEGIN IMMEDIATE` + 主键唯一约束，并发请求只有一个能成功）
- 🚫 **主体级撤销**：管理员可按 `subject` 设置撤销截止时间，`iat` 不晚于截止时间的
  令牌一律 401；撤销判断与 nonce 消费在**同一个 SQLite 事务**中完成，被撤销的令牌
  不会消耗 nonce，且支持一键恢复
- 🚀 启动时自动初始化数据库，监听 **8000** 端口
- 🐳 提供 `Dockerfile` 与 `docker-compose.yml`，开箱即用

---

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── config.py        # 环境变量配置
│   ├── db.py            # SQLite：nonce 原子消费、主体撤销记录与过期清理
│   ├── tokens.py        # 令牌签发 / 解析 / 验证（HMAC 核心）
│   ├── schemas.py       # Pydantic 请求/响应模型
│   └── main.py          # FastAPI 路由与启动生命周期
├── files/               # 受保护的示例下载目录（compose 只读挂载）
│   └── hello.txt
├── tests/
│   └── test_api.py      # 47 个端到端/配置测试（无需网络/容器）
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
└── README.md
```

## 快速开始

### 方式一：Docker Compose（推荐）

```bash
cp .env.example .env          # 按需修改 CAPABILITY_KEYRING（默认开发密钥可直接启动）
docker compose up --build
```

服务在 `http://localhost:8000` 启动，交互式文档位于
`http://localhost:8000/docs`。

### 方式二：本地运行

```bash
pip install -r requirements.txt
export CAPABILITY_KEYRING="2026-09:$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
# 或：python -m app.main
```

> 未配置任何密钥（`CAPABILITY_KEYRING` 与 `CAPABILITY_SECRET` 均为空）时，服务会在启动时
> 生成**进程内随机密钥**（kid=`ephemeral`），重启后所有旧令牌失效（日志会有 WARNING）。
> 开发可用，生产请务必固定密钥环。

### 健康检查

```bash
curl http://localhost:8000/health
# {"status":"ok","time":1727000000}
```

## 使用流程

### 1. 签发令牌

```bash
curl -X POST http://localhost:8000/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "method": "GET",
    "path": "/files/hello.txt",
    "ttl_seconds": 120,
    "one_time": true,
    "subject": "alice"
  }'
```

响应：

```json
{
  "token": "eyJleHAi...LjU...（base64url(payload).base64url(hmac)）",
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "kid": "2026-09",
  "method": "GET",
  "path": "/files/hello.txt",
  "issued_at": 1727000000,
  "expires_at": 1727000120,
  "expires_in": 120,
  "one_time": true,
  "subject": "alice"
}
```

请求字段：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `method` | 是 | 令牌绑定的 HTTP 方法（规范为大写），如 `GET`、`POST`、`DELETE` |
| `path` | 是 | 令牌绑定的路径，必须以 `/` 开头，如 `/files/hello.txt` |
| `ttl_seconds` | 否 | 有效期秒数；缺省用 `CAPABILITY_DEFAULT_TTL`，并被 `CAPABILITY_MAX_TTL` 截断 |
| `one_time` | 否 | `true` 表示一次性令牌，首次成功使用即失效 |
| `subject` | 否 | 令牌归属主体（如用户 ID），会写入签名负载 |
| `extra` | 否 | 任意额外 JSON 声明（同样受签名保护，篡改即签名失败） |

### 2. 使用令牌访问受保护资源（文件下载）

支持三种携带方式（任选其一）：

```bash
# 查询参数
curl -i "http://localhost:8000/files/hello.txt?token=<TOKEN>"

# Authorization 头（Bearer 或 Capability 方案均可）
curl -i -H "Authorization: Bearer <TOKEN>" \
  http://localhost:8000/files/hello.txt

# 自定义头
curl -i -H "X-Capability-Token: <TOKEN>" \
  http://localhost:8000/files/hello.txt
```

一次性令牌**第一次成功下载返回 200**，再次使用返回：

```json
HTTP/1.1 401 Unauthorized
{"error":"nonce_replayed","detail":"one-time token has already been used"}
```

### 3. 独立验证令牌（不访问资源）

适合网关 / 其它服务在转发前做校验：

```bash
curl -X POST http://localhost:8000/tokens/verify \
  -H 'Content-Type: application/json' \
  -d '{
    "token": "<TOKEN>",
    "method": "GET",
    "path": "/files/hello.txt",
    "consume": true
  }'
```

- `consume: true`（默认）：若为一次性令牌且验证通过，会**真正消费 nonce**。
- `consume: false`：只做"演练"（dry run），不消费一次性令牌，可用于预检。

成功响应：

```json
{
  "valid": true,
  "method": "GET",
  "path": "/files/hello.txt",
  "expires_at": 1727000120,
  "expires_in": 97,
  "one_time": true,
  "consumed": true,
  "token_id": "z1w6w4XPKcDQ2mkotgWgng",
  "kid": "2026-09",
  "subject": "alice",
  "extra": {}
}
```

### 4. 主体级撤销（管理员接口）

当某个用户（`subject`）的令牌泄露或需要强制下线时，无需轮换签名密钥，按主体撤销即可。
接口由 `CAPABILITY_ADMIN_KEY` 保护（请求头 `X-Admin-Key`）；**未配置该变量时接口整体
返回 503 `admin_key_not_configured`（fail closed）**，不会裸奔。

```bash
# 撤销：alice 在截止时间（含）之前签发的所有令牌立即失效；
# 省略 cutoff 时默认为当前时间
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "cutoff": 1727000000}'
# {"subject":"alice","revoked":true,"restored":false,"cutoff":1727000000,
#  "created_at":1727000001,"updated_at":1727000001}

# 之后 alice 的旧令牌验证返回（nonce 不会被消耗）：
# HTTP/1.1 401 Unauthorized
# {"error":"subject_revoked","detail":"subject 'alice' is revoked ..."}

# 查看当前全部撤销记录
curl http://localhost:8000/tokens/revocations \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY"
# {"revocations":[{"subject":"alice","cutoff":1727000000,...}],"count":1}

# 恢复：解除对 alice 的撤销（截止时间之后签发的令牌本就不受影响）
curl -X POST http://localhost:8000/tokens/revoke-subject \
  -H "X-Admin-Key: $CAPABILITY_ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"subject": "alice", "restore": true}'
# {"subject":"alice","revoked":false,"restored":true,...}
```

要点：

- 判定依据是令牌负载中的 `iat`（签发时间）：`iat <= cutoff` 即拒绝，与令牌剩余
  有效期无关；`iat > cutoff` 的令牌（撤销后新签发的）不受影响；
- 撤销记录持久化在 SQLite（`subject_revocations` 表），重启后仍然有效；
- 当 `cutoff + CAPABILITY_MAX_TTL <= now` 时，该记录能命中的令牌必然已全部过期，
  后台清理任务（每 10 分钟，启动时也会执行一次）会自动将其删除，表不会无限增长；
- 撤销对多用途令牌（`one=false`）同样生效——它们原本完全无状态，撤销是唯一的
  服务端状态依赖；不带 `subject` 的令牌不参与撤销，依旧完全无状态。

Docker Compose 场景下把 `CAPABILITY_ADMIN_KEY` 写进 `.env`（见 `.env.example`），
然后在宿主机直接执行上面的 curl 即可（compose 默认映射 `8000:8000`）。

## 验证规则（核心）

`verify_token` 按以下顺序检查，任何一步失败立即返回稳定错误码：

1. **结构**：令牌必须为 `<base64url(payload)>.<base64url(signature)>`，payload 是 JSON 对象；
2. **选键（按 `kid` 精确选择，绝不遍历试签）**：
   - 负载含 `kid`：只在密钥环中查找该 id；找不到直接返回
     `401 unknown_key`，**不会**再尝试其它任何密钥；
   - 负载不含 `kid`（轮换前的旧格式令牌）：**只**用
     `CAPABILITY_LEGACY_SECRET` 校验；未配置旧密钥时返回 `401 unknown_key`；
3. **签名**：用选定的那一把密钥计算 `HMAC-SHA256(secret, payload)`，与令牌附带签名用
   `hmac.compare_digest` 常量时间比较，防止时序攻击；
4. **负载声明**：版本号 `v=1`，`kid`（存在时）/`m`/`p`/`jti` 为非空字符串，
   `iat`/`exp` 为整数且 `iat <= exp`，`one` 为布尔；
5. **过期时间**：当前时间 `>= exp` 即拒绝（`expired`）；
6. **方法绑定**：令牌方法 ≠ 请求方法返回 `403 method_mismatch`；
7. **路径绑定**：令牌路径 ≠ 规范化后的请求路径返回 `403 path_mismatch`；
8. **主体撤销 + 一次性 nonce**：在**同一个 `BEGIN IMMEDIATE` 事务**中先查
   `subject_revocations`（`iat <= cutoff` 则返回 `401 subject_revoked`，且不消耗
   nonce），再在需要时原子写入 `consumed_nonces`（已存在则返回 `nonce_replayed`）。
   撤销与验证并发竞争时由事务串行化裁决：要么验证先提交（nonce 已消费、撤销后至），
   要么撤销先生效（验证被拒、nonce 保留），绝不出现"被撤销却烧掉 nonce"的中间态。

### 路径规范化

签发与验证使用同一套规则（`app/tokens.py::canonical_path`），保证双方对路径的理解一致：

- 折叠重复斜杠（包括前导 `//`）；
- 解析 `.` / `..` 段；
- 去掉根路径以外的结尾 `/`。

因此 `/files/hello.txt` 与 `//files/./hello.txt/` 视为同一绑定。受保护下载端点还会在
文件系统层做 `Path.resolve()` 边界检查，杜绝目录穿越。

### 错误码

| `error` | HTTP 状态码 | 含义 |
| --- | --- | --- |
| `malformed` | 401 | 令牌格式/base64/JSON 错误 |
| `bad_signature` | 401 | HMAC 签名不匹配（令牌被篡改或密钥不同） |
| `bad_payload` | 401 | 负载声明类型/版本非法 |
| `expired` | 401 | 令牌已过期 |
| `unknown_key` | 401 | 令牌 `kid` 不在密钥环中（未知/已退役），或无 `kid` 的旧令牌没有配置 `CAPABILITY_LEGACY_SECRET` |
| `nonce_replayed` | 401 | 一次性令牌被重复使用 |
| `subject_revoked` | 401 | 主体已被撤销（`iat` 不晚于撤销截止时间） |
| `method_mismatch` | 403 | HTTP 方法与绑定不一致 |
| `path_mismatch` | 403 | 路径与绑定不一致 |
| `unauthorized` | 401 | 缺少或错误的 `X-Issuer-Key` / `X-Admin-Key` |
| `admin_key_not_configured` | 503 | 未配置 `CAPABILITY_ADMIN_KEY`，管理接口未启用 |
| `validation_error` | 422 | 请求体未通过 Pydantic 校验 |

## 令牌格式

```
<base64url(payload_json)>.<base64url(hmac_sha256(secret, payload_json))>
```

负载（紧凑 JSON，签发时键按字典序规范化，全部纳入签名）：

```json
{
  "v": 1,
  "kid": "2026-09",
  "m": "GET",
  "p": "/files/hello.txt",
  "iat": 1727000000,
  "exp": 1727000120,
  "jti": "z1w6w4XPKcDAQ2mkotgWgng",
  "one": true,
  "sub": "alice",
  "ext": {}
}
```

- `kid` 是签名密钥在密钥环中的标识（**同样受签名保护**），验签时按它精确选键；
  轮换前签发的旧令牌没有这一项，只能用 `CAPABILITY_LEGACY_SECRET` 校验；
- 多用途令牌（`one=false`）**完全无状态**：只靠签名和过期即可验证，数据库不记录任何东西；
- 一次性令牌只在服务端记住一个不透明 nonce（`jti`），不存储令牌或负载内容。

## 无中断 HMAC 密钥轮换

轮换不需要停机，也不会让未过期的旧令牌失效。密钥通过 `CAPABILITY_KEYRING` 配置——
一个**有序**的逗号分隔列表，每项为 `kid:secret`：

- **首项 = 当前签发密钥**：新令牌的签名负载写入它的 `kid`，签发响应里也会回显；
- **其余项 = 仅用于验签的旧密钥**：令牌携带哪个 `kid`，就用哪一把密钥验签，
  **绝不遍历密钥环逐把试签**；
- **移除某 kid 后立即拒绝**：该 kid 签发的令牌（哪怕未过期）一律
  `401 unknown_key`；
- 启动时严格校验：**重复 kid、空密钥、缺少 `:` 分隔符、非法 kid** 都会直接报错退出；
  `CAPABILITY_KEYRING` 与 `CAPABILITY_SECRET` 同时设置也属于冲突配置，拒绝启动。

推荐三步轮换（TTL 最长 1 小时的场景，等待一个 `CAPABILITY_MAX_TTL` 即可清理旧键）：

```bash
# 1) 生成新密钥，放到列表首位；旧密钥下移，继续负责旧令牌验签
NEW_SECRET="$(python -c 'import secrets;print(secrets.token_urlsafe(32))')"
#    .env 中改为：
#    CAPABILITY_KEYRING=2026-12:<NEW_SECRET>,2026-09:<PREVIOUS_SECRET>
docker compose up -d

# 2) 部署后新签发的令牌 kid=2026-12；未过期的旧令牌照常验证
curl -s -X POST http://localhost:8000/tokens/issue \
  -H 'Content-Type: application/json' \
  -d '{"method":"GET","path":"/files/hello.txt"}' | grep kid
#   "kid": "2026-12"

# 3) 等所有 kid=2026-09 的令牌过期（>= CAPABILITY_MAX_TTL）后，删掉该项即完成轮换
#    CAPABILITY_KEYRING=2026-12:<NEW_SECRET>
```

### 兼容轮换前的旧令牌

升级本功能前签发的令牌负载里没有 `kid`。这类令牌**只会**用
`CAPABILITY_LEGACY_SECRET` 校验，密钥环中的任何密钥都不会拿来对它们试签：

- 升级时把旧的 `CAPABILITY_SECRET` 值原样设为 `CAPABILITY_LEGACY_SECRET`，
  旧令牌在过期前继续可用；确认全部过期后清空该变量，之后无 `kid` 令牌一律
  `401 unknown_key`；
- 反过来，带 `kid` 的令牌即使其密钥值恰好等于旧密钥，也必须按 `kid` 在环中选键，
  不会落到旧密钥通道。

> **向后兼容**：只设置老变量 `CAPABILITY_SECRET` 仍可一键启动——它同时充当签发密钥
> （kid=`default`）与旧令牌验签密钥，行为与升级前完全一致；但它不能与
> `CAPABILITY_KEYRING` 同时出现（启动会报冲突）。

## 一次性 nonce 的原子性（防重放）

`app/db.py` 使用 SQLite：

```sql
CREATE TABLE consumed_nonces (
    nonce      TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
) WITHOUT ROWID;

CREATE TABLE subject_revocations (
    subject    TEXT PRIMARY KEY,
    cutoff     INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
) WITHOUT ROWID;
```

消费逻辑在一个 `BEGIN IMMEDIATE` 事务中执行
`INSERT OR IGNORE`，以 `rowcount == 1` 判定是否为首次使用。数据库级主键唯一约束会把
并发竞争串行化：**N 个并发重放恰好 1 个成功，其余全部拿到 `nonce_replayed`**
（测试 `test_15_concurrent_replays_only_one_wins` 及真实 HTTP 8 并发冒烟均验证过）。

主体撤销检查与 nonce 消费**共用同一个事务**（见上一节第 7 步），因此：

- 12 线程并发验证一个"已被撤销的一次性令牌"：全部得到 `subject_revoked`，nonce 原样
  保留，恢复后仍可正常使用（`test_31`）；
- 8 个一次性令牌与一次撤销并发竞争：每个令牌要么验证成功（nonce 已消费），要么被撤销
  （nonce 未消费），恢复后重验结果与之一一对应（`test_32`）。

`expires_at` 冗余入库，后台每 10 分钟（启动时也会执行一次）清除已过期行；撤销记录在
`cutoff + CAPABILITY_MAX_TTL <= now`（即能命中的令牌必然已全部过期）后一并清除，
保证两张表都不无限增长。

## 配置项（环境变量）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `CAPABILITY_KEYRING` | （未设置） | 有序逗号分隔 `kid:secret` 列表；**首项签发新令牌**，全部项按 `kid` 精确验签。kid 限 1–128 个 `[A-Za-z0-9._-]` 字符，密钥非空（可含 `:`），kid 不可重复 |
| `CAPABILITY_LEGACY_SECRET` | 空（拒绝无 kid 旧令牌） | 无 `kid` 旧令牌的**唯一**验签密钥；不用于带 kid 的令牌，也不触发密钥遍历 |
| `CAPABILITY_SECRET` | （启动时随机生成） | **已废弃的单密钥模式**：未配置 keyring 时同时作为签发密钥（kid=`default`）和旧令牌密钥；与 `CAPABILITY_KEYRING` 同时设置会启动失败 |
| `CAPABILITY_ISSUER_KEY` | 空（签发不鉴权） | 设置后，调用 `/tokens/issue` 须带匹配的 `X-Issuer-Key` 头 |
| `CAPABILITY_ADMIN_KEY` | 空（管理接口停用） | 设置后，调用 `/tokens/revoke-subject`、`/tokens/revocations` 须带匹配的 `X-Admin-Key` 头；未设置时这两个接口返回 503 |
| `CAPABILITY_DB_PATH` | `./data/capabilities.db` | SQLite 文件路径，启动自动建库建表 |
| `CAPABILITY_FILES_DIR` | `./files` | 受保护下载目录 |
| `CAPABILITY_DEFAULT_TTL` | `300` | 默认有效期（秒） |
| `CAPABILITY_MAX_TTL` | `3600` | 有效期硬上限（秒） |

> 签发鉴权是可选项：能力令牌通常由内部可信服务签发，因此用环境变量配置一个共享密钥
> 即可，无需用户体系或第三方账号。

## 运行测试

测试通过 FastAPI `TestClient` 在进程内运行，自动使用临时目录，不影响任何真实数据：

```bash
# 若环境里没有 pytest，直接用 unittest 运行也可以：
python tests/test_api.py
```

覆盖：签发与 TTL 截断、路径规范化、签发密钥门禁、签名篡改、负载篡改、方法/路径绑定、
过期、畸形令牌、一次性消费、dry-run、**12 线程并发重放只有 1 个成功**、无令牌下载、
三种携带方式、HEAD/GET 绑定、缺失文件、目录穿越、健康检查，主体撤销相关的
管理端点鉴权（503/401）、撤销后旧令牌失效新令牌不受影响、截止时间边界（`iat == cutoff`
也被撤销）、**被撤销的一次性令牌不消耗 nonce**、恢复（含对未撤销主体的幂等恢复）、
撤销列表、dry-run 同样受撤销约束、**12 线程并发验证全部被撤销拦截**、
**8 令牌与撤销并发竞争的原子性**、过期撤销记录清理，以及**密钥轮换**：新令牌写入当前
kid、保留旧 kid 继续验签、移除 kid 立即 `unknown_key`、未知 kid 拒绝、无 kid 旧令牌
仅用 legacy 密钥（用环内密钥伪造的旧格式令牌必须 `bad_signature`，证明不做遍历试签）、
篡改 kid 后按新选键验签失败、非字符串 kid 为 `bad_payload`，以及密钥环解析与启动期
冲突校验（重复 kid、空密钥、非法条目、keyring 与单密钥互斥、legacy 必须成对配置、
单密钥向后兼容、无密钥时生成临时密钥）共 47 个用例。

## 部署说明

- Compose 将 SQLite 放在命名卷 `capability-data`（`/data`），把宿主机 `./files`
  只读挂载到 `/app/files`；
- 容器以非 root 用户（uid 10001）运行，并内置 `/health` 健康检查；
- 多副本部署时 SQLite 文件需放在共享块存储上，或将本服务作为单实例网关运行；
  也可自行把 `Database` 替换为其它支持唯一约束的存储而不改动令牌核心逻辑。

## 安全建议

1. 生产环境始终通过 `CAPABILITY_KEYRING` 配置强随机密钥并由密钥管理机制注入，不要提交到仓库；
   轮换按「新密钥置顶 → 等待一个 `CAPABILITY_MAX_TTL` → 删除旧 kid」进行，无需停机；
2. TTL 尽量短（分钟级），需要防重放的场景使用 `one_time=true`；
3. 令牌应通过 HTTPS（TLS）传输，查询参数形式可能出现在访问日志中，敏感场景优先用请求头；
4. 升级后把旧 `CAPABILITY_SECRET` 值临时放入 `CAPABILITY_LEGACY_SECRET` 以兼容存量无 `kid`
   令牌，待其全部过期后清空；不要长期保留旧 kid/旧密钥；
5. 撤销管理接口务必配置强随机 `CAPABILITY_ADMIN_KEY` 并只在管理面暴露；未配置时接口
   自动停用（503），不存在"忘记配置就裸奔"的窗口。
