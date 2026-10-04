# CubeDemo / CubeDemoNC 现场冒烟记录

| 项 | 内容 |
| --- | --- |
| 日期 | 2026-10-04 |
| 代码 | `master` @ `65cd9af6` |
| 对照 | 审计编号来自 `origin/cursor/security-audit-a47b` 的 `docs/security/SECURITY_AUDIT.md`（该文件不在本次 `master` 上） |
| 范围 | 只在本机启动两个演示主机，用普通 GET 看状态码、响应头和页面是否出现已知提示 |
| 未做 | 不提交登录凭据，不猜测口令，不构造利用请求，不保存接口或附件正文 |

结论用语：已确认 / 未复现 / 未测试 / 未行使（default off）。功能默认关闭时不把对应发现改判成未复现。

## 1. 怎么启动

两个项目都是 `net10.0` 的 Web SDK 项目。本机原先没有 `dotnet`，冒烟前安装了 SDK `10.0.401`。

| 项目 | 工程 | 配置里的地址 | 本次实际地址 |
| --- | --- | --- | --- |
| CubeDemo | `CubeDemo/CubeDemo.csproj` | `launchSettings.json` 为 `https://localhost:7116` | `http://127.0.0.1:5116` |
| CubeDemoNC（即 CubeNCDemo） | `CubeDemoNC/CubeDemoNC.csproj` | `launchSettings.json` 与 `appsettings.json` 为 `http://*:7080` 和 `https://*:7081` | `http://127.0.0.1:7080` |

数据库沿用演示工程里已经生效的 SQLite，没有改连接串，也没有指向外部系统：

- `Membership` / `Cube` / `Log` → `Data Source=..\Data\*.db;provider=sqlite`
- 进程实际写到本机 `/workspace/Bin/Data/`（`Cube.db`、`Membership.db`、`Log.db`）

构建（Debug，0 error）：

```bash
dotnet build CubeDemo/CubeDemo.csproj -c Debug
dotnet build CubeDemoNC/CubeDemoNC.csproj -c Debug
```

CubeDemo 220 条 warning，CubeDemoNC 118 条 warning，都没有阻止编译。

启动（Development，不用 launch profile，避免开发证书和 `*` 监听）：

```bash
ASPNETCORE_ENVIRONMENT=Development \
dotnet run --project CubeDemo/CubeDemo.csproj --no-launch-profile --no-build -c Debug \
  --urls http://127.0.0.1:5116

ASPNETCORE_ENVIRONMENT=Development \
dotnet run --project CubeDemoNC/CubeDemoNC.csproj --no-launch-profile --no-build -c Debug \
  --urls http://127.0.0.1:7080
```

检查结束后已停止两个进程。`127.0.0.1:5116` 与 `127.0.0.1:7080` 已关闭。

## 2. 启动结果

| 主机 | 结果 | 监听 | 启动异常 |
| --- | --- | --- | --- |
| CubeDemoNC | 通过 | 日志有 `Now listening on: http://127.0.0.1:7080`，环境 Development，内容根 `/workspace/CubeDemoNC` | 未见未处理启动异常 |
| CubeDemo | 通过（进程起来了，初始化有异常） | 日志有 `Now listening on: http://127.0.0.1:5116`，环境 Development，内容根 `/workspace/CubeDemo` | 见下 |

CubeDemo 与 CubeDemoNC 同时使用同一组 SQLite 文件。CubeDemo 启动日志中有：

- `System.IO.IOException`：无法独占打开 `/workspace/Bin/Data/Cube.db`（另一进程正在使用）
- `XCode.Exceptions.XSqlException`：向已由另一演示初始化的 `Menu` 插入时触发 UNIQUE 约束
- `XCode.Exceptions.XSqlException`：`SQL logic error` / `no such table: AccessRule`（初始化数据出错）

这些异常没有让进程退出。之后仍打印 Application started，并且下面的 HTTP 检查都打到了这个端口。

## 3. 每个主机看到的 HTTP

请求都是 GET，带了 `Origin: https://example.invalid`，不跟随重定向，不提交表单。附件和文档 JSON 的正文已丢弃，这里只记状态、类型和长度。

### 3.1 CubeDemo `http://127.0.0.1:5116`

| 检查 | 结果 |
| --- | --- |
| `GET /` | 404，空正文。没有开发者异常页标记 |
| 登录页 `GET /Admin/User/Login` | 404，空正文。页面上没有 `admin/admin` |
| `GET /Auth/Login` | 405（该地址不接受这次 GET） |
| 公开配置 `GET /Auth/LoginConfig` | 200，JSON。`challengeRequired=false`，`loginTip` 为空，没有 `admin/admin`。`loginPassword=true`，`loginSms=false`，`loginMail=false`，`registerEnabled=true`，`mfaAvailable=false`。响应里没有 `AllowPlainPassword` 这个字段名 |
| `GET /Cube/Info`、`/cube/info` | 200 |
| `GET /Cube/Apis`、`/cube/apis` | 200 |
| 附件 `GET /Cube/File?id=0`、`/Cube/Image?id=0.png`、`/cube/file?id=0.bin` | 都是 200，`Content-Type: application/json`，长度 49 字节。正文丢弃，没有保存文件内容 |
| 良性 404 `GET /this-page-does-not-exist-smoke` | 404，空正文，没有开发者异常页 |
| CORS（上述简单 GET） | `Access-Control-Allow-Origin: https://example.invalid`，`Access-Control-Allow-Credentials: true` |
| Swagger UI `GET /swagger/index.html` | 200，`text/html`，无 `WWW-Authenticate` |
| `GET /swagger` | 301，`Location: swagger/index.html` |
| `GET /swagger/v1/swagger.json` | 200，`application/json`。正文丢弃，未记录内容 |
| Scalar `GET /scalar`、`/scalar/v1` | 401，`WWW-Authenticate: Basic realm="Scalar"`。没有提交文档口令 |
| 文件管理 `GET /Admin/File` | 404 |
| 文件管理 `GET /api/Admin/File` | 401，JSON，长度 55 字节。正文丢弃。不是目录列表 |

未登录时每次响应都带 Set-Cookie（没有提交凭据）：

| Cookie 名 | HttpOnly | Secure | SameSite |
| --- | --- | --- | --- |
| `.Cube.Session` | 无 | 无 | 未设置 |
| `CubeDeviceId0` | 有 | 无 | 未设置 |

没有出现登录令牌 Cookie。

### 3.2 CubeDemoNC `http://127.0.0.1:7080`

| 检查 | 结果 |
| --- | --- |
| `GET /` | 200，`text/html`，约 618 字节。没有 `admin/admin`，没有表单 |
| 登录页 `GET /Admin/User/Login` | 200，`text/html`，约 14 KB，有登录表单。页面含 `admin/admin` 提示。没有 `AllowPlainPassword` 字样，也没有 `__RequestVerificationToken` |
| 公开配置 `GET /Admin/Cube/GetLoginConfig` | 200，JSON。布尔值与 CubeDemo 的 `/Auth/LoginConfig` 相同：`challengeRequired=false`，登录提示为空。页面上的 `admin/admin` 不在这份 JSON 里 |
| `GET /Cube/Info`、`/Cube/Apis` | 200 |
| 附件 `GET /Cube/File?id=0`、`/Cube/Image?id=0.png`、`/cube/file?id=0.bin` | 都是 404，`text/plain`，长度 21 字节。正文丢弃 |
| 良性 404 | 404，空正文，没有开发者异常页 |
| CORS | 与 CubeDemo 相同：反射本次 `Origin`，且 `Access-Control-Allow-Credentials: true` |
| `/swagger`、`/swagger/index.html`、`/swagger/v1/swagger.json`、`/scalar`、`/scalar/v1` | 都是 404。这个主机没有挂 Swagger/Scalar |
| 文件管理 `GET /Admin/File` | 302，`Location: /Admin/User/Login?r=%2fAdmin%2fFile`。未跟随 |
| 文件管理 `GET /api/Admin/File` | 404 |

未登录 Set-Cookie 与 CubeDemo 相同：`.Cube.Session` 无 HttpOnly、无 Secure、无 SameSite；`CubeDeviceId0` 有 HttpOnly，无 Secure，无 SameSite。没有登录令牌 Cookie。

## 4. 审计编号

| ID | 本次结论 | 依据（只来自上面的普通响应） |
| --- | --- | --- |
| CUBE-INFO-022 | 已确认 | 两个主机匿名 GET `/Cube/Info` 与 `/Cube/Apis` 都是 200。未记录正文 |
| CUBE-DEF-015 | 已确认（CORS 与明文口令开关）；调试异常页未复现 | 简单 GET 反射任意 Origin 且允许凭据。公开登录配置 `challengeRequired=false`（挑战应答不是必填）。良性 404 是空 404，没有开发者异常页。公开配置里自助注册为开启；没有去注册 |
| CUBE-SECRET-021 | 文档口令未行使；Swagger UI 可达性已确认 | CubeDemo 的 Swagger UI 与 `/swagger/v1/swagger.json` 未认证即 200。Scalar 为 401。没有提交文档站点口令。CubeDemoNC 上这些路径是 404 |
| CUBE-SESS-006 | 未测试 | 发现针对的是登录令牌 Cookie。本次没有提交凭据，响应里没有该 Cookie。匿名会话 Cookie 的标志见第 3 节，不能代替这条 |
| CUBE-CSRF-007 | 未测试 | 未进入新增/编辑表单。CubeDemoNC 登录页没有防伪字段，但那不是这条所指的编辑表单 |
| CUBE-FILE-011 | 未行使（default off） | 没有打开文件管理，也没有拿到目录列表。CubeDemo `/api/Admin/File` 为 401；CubeDemoNC `/Admin/File` 为 302 到登录页。没有看到审计里写的关闭态 403 |
| CUBE-OTP-008 | 未行使（default off） | 公开配置里短信、邮箱登录都是 false。没有发码，也没有提交验证码 |
| CUBE-TENANT-016 | 未行使（default off） | 没有发带租户条件的数据请求。CubeDemoNC 启动日志里把 `TenantEnforceMode` 写成了 Shadow，没有用 HTTP 验证“无租户则放行” |
| CUBE-JOB-020 | 未行使（default off） | 没有打开定时作业，也没有提交 SQL |
| CUBE-AUTH-001 | 未测试 | 密码模式需要专门构造的令牌请求 |
| CUBE-AUTH-002 | 未测试 | 需要第三方登录回调 |
| CUBE-AUTH-003 | 未测试 | 需要 IdP 角色声明 |
| CUBE-OAUTH-004 | 未测试 | 需要授权码兑换 |
| CUBE-OAUTH-005 | 未测试 | 回调白名单绕过不在本次观察范围 |
| CUBE-AUTH-012 | 未测试 | |
| CUBE-OAUTH-013 | 未测试 | |
| CUBE-LOG-014 | 未测试 | |
| CUBE-AUTHZ-010 | 未测试 | 没有使用应用密钥或用户令牌 |
| CUBE-NET-009 | 未测试 | 没有伪造转发头 |
| CUBE-SSRF-017 | 未测试 | |
| CUBE-XSS-018 | 未测试 | 只读到登录页已有提示，没有提交标记 |
| CUBE-TOKEN-019 | 未测试 | |
| CUBE-APP-023 | 未测试 | 未知 client_id 会写应用表 |
| CUBE-CRYPTO-024 | 未测试 | 没有请求公钥接口 |
| CUBE-STORE-026 | 未测试 | 附件请求只用了不存在的 `id=0`，看状态码，不测路径穿越 |
| CUBE-SQL-027 | 未测试 | |
| CUBE-ZIP-028 | 未测试 | |
| CUBE-DEP-025 | 范围外 | 按本次要求不复现、也不标失败。构建时仓库仍关闭 NuGetAudit，这里不下结论 |

登录页 `admin/admin` 提示不是单独的审计编号：CubeDemoNC 的 `/Admin/User/Login` 已确认仍有这段提示；CubeDemo 没有 Razor 登录页，公开配置里的登录提示为空，这次响应里未复现。

## 5. 本次明确不做、也不标失败

- 仓库里的 snk
- CI 的 NuGet 推送
- NuGetAudit（CUBE-DEP-025）
- lockfile

## 6. 限制

两个演示共用 `Bin/Data` 下的 SQLite，所以 CubeDemo 的初始化异常和“同时跑两个进程”有关，不能单独当成这个程序在空库上的启动失败。HTTP 观察发生在进程已经监听之后。没有登录，因此登录后才会出现的 Cookie、编辑表单和文件管理开启后的行为都没有覆盖。
