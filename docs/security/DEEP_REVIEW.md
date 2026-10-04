# NewLife.Cube 深度防御复查

| 项 | 内容 |
| --- | --- |
| 文档名称 | NewLife.Cube 深度防御复查 |
| 评估对象 | 本 fork：`NewLife.Cube`（当前 WebAPI 主库）、`NewLife.CubeNC`（MVC / 历史副本，部分源文件被主库 Link）、示例宿主 `CubeDemo`、`CubeDemoNC`、`CubeSSO` |
| 评估日期 | 2026-10-04 |
| 基线 | `master` @ `65cd9af6` |
| 对照文档 | `origin/cursor/security-audit-a47b` 上的 `docs/security/SECURITY_AUDIT.md`（工作区 `master` 尚未包含该文件）。全库检索无 `docs/security/LIVE_SMOKE.md`，因此没有可跳过的线上冒烟条目 |
| 方法 | 静态阅读与属性清点。未启动示例，未登录，未发送请求，未构造利用输入 |
| 范围外 | NewLife.Core、XCode、NewLife.AI、Stardust 包内部实现。依赖这些包才能判定的结论标为 Needs Verification |

## 1. 执行摘要

第一轮报告里的关键代码仍然在。本次没有推翻 `CUBE-AUTH-001` 到 `CUBE-ZIP-028` 的代码事实，只收窄了 `CUBE-SESS-006` 的默认影响面：服务端登录 Cookie 的不安全标志还在，但 `TokenCookie` 默认为 `false`，库存安装不会写出那枚 Cookie。

本轮新的重点不在“再讲一遍 OAuth 密码模式”，而在第一轮写得较轻的整库路径：

- 附件下载在默认配置下，任意已登录用户可以读取未列入“仅所有者”分类的附件；`Image` / `File` 还绕过外层令牌门闩。
- 实体基类 `UploadFile` 没有菜单权限特性，任意已登录用户即可上传。
- 定时作业按数据库里的类型名反射执行，不限于已文档化的 SQL 作业。
- 外部认证把口令转发到配置的 URL，并按手机、邮箱接管已有账号、按角色名占用已有角色。
- 多租户中间件把实体层数据范围设成“全部”，行级隔离只靠控制器特性和 `ITenantScope`。
- 一批状态变更走 GET，补上表单防伪令牌也盖不住。
- 数据库管理接口把连接串放进响应；配置保存日志会记下属性旧值和新值。

| 级别 | 新编号 | 说明 |
| --- | --- | --- |
| High | 4 | 附件读、上传、作业反射、外部认证 |
| Medium | 7 | 数据范围、GET 状态变更、会话 Cookie、连接串、AI 脚本、配置日志、示例控制器 |
| Low / Info | 3 | 匿名元数据、菜单树、CI 与前端令牌存储 |
| Needs Verification | 4 | 示例租户接口、排序 SQL、解压、AI/星尘出站 |

## 2. 与第一轮的对照

| 原编号 | 本次结论 |
| --- | --- |
| CUBE-AUTH-001 | **确认**。`TokenService.GetAccessTokenByPassword` 仍有 `md5#` 分支，空库存口令会跳过比较（`NewLife.Cube/Services/Sso/TokenService.cs`） |
| CUBE-AUTH-002 / 003 | **确认**，并另有更强路径 `CUBE-AUTH-104`。`UserBindingService` 的默认绑定与 `UseSsoRole` 未在本轮逐行重写，外部认证是另一条绑定与角色通道 |
| CUBE-OAUTH-004 / 005 | **确认仍在**（授权码与回调）。本轮未重读完整兑换函数，不新增编号 |
| CUBE-SESS-006 | **代码确认，默认影响收窄**。`SaveCookie` 仍不设 `HttpOnly`，HTTPS 仍把 `SameSite` 设为 `None`。`CubeSetting.TokenCookie` 默认为 `false`，该函数开头直接返回。风险在打开“令牌 Cookie”之后，而不是每一台新安装 |
| CUBE-CSRF-007 | **确认**。`EditForm.cshtml`、`Form.cshtml` 的防伪令牌仍被注释。另见 `CUBE-CSRF-108`：若干状态变更是 GET，表单令牌覆盖不到 |
| CUBE-OTP-008 / CUBE-NET-009 | **未重测生成函数与转发头**。本轮没有看到推翻它们的改动，也没有更强的新代码路径 |
| CUBE-AUTHZ-010 | **确认**。`CubeController.ValidateToken` 仍把启用应用的 Secret、空 Url 的 `UserToken` 当作通行证，令牌仍可读查询串。附件动作是例外，见 `CUBE-FILE-102` |
| CUBE-FILE-011 | **确认**。`FileController.Root` 仍是 `"../".GetCurrentPath()`，文件管理默认关闭。本轮更关心默认开启的附件接口 |
| CUBE-LOG-014 | **确认**。`SsoController` 失败日志仍包含 `client_secret`，刷新日志包含 `refresh_token`，`TokenService.GetToken` 仍把访问令牌写入日志 |
| CUBE-DEF-015 | **确认**。`Debug`、`AllowPlainPassword`、`EnableOAuthServer`、CORS `*` 与凭据并存等默认值未改。另见 `FileStorageProvide` / `FileStorageFetch` 默认 `true` |
| CUBE-TENANT-016 | **确认**。`CreateWhere` 在影子模式且无租户上下文时不加过滤。另见 `CUBE-SCOPE-106`：中间件主动关闭实体层数据范围 |
| CUBE-SSRF-017 | **确认调用点仍在**。`附件.Fetch`、`UserBindingService.FetchAvatar`、`DefaultLovListDataProxy.FetchAsync`、`Jobs/HttpService` 都按配置或库存 URL 出站，没有本仓库内的地址黑名单。`Image`/`File` 在本地文件缺失时会调用 `att.Fetch(att.Source)`，这是自动触发，不是单独的管理动作 |
| CUBE-XSS-018 | **未逐个重读视图**。`ListField` 与登录提示的编码问题不在本轮新发现里重复展开 |
| CUBE-JOB-020 | **确认，且范围更大**。见 `CUBE-JOB-103` |
| CUBE-SECRET-021 | **确认**。`SwaggerService` 默认口令、`CubeDemo/appsettings.json` 与 `CubeDemoNC/appsettings.json` 注释中的 `Uid=root;Pwd=root` 仍在 |
| CUBE-DEP-025 | **确认**。`Directory.Build.props` 仍是 `<NuGetAudit>false</NuGetAudit>`。CI 的 `test.yml` 只做 build 与 test，没有漏洞审计 |
| CUBE-STORE-026 / SQL-027 / ZIP-028 | **仍为 Needs Verification**。`LocalAttachmentStorage.GetFullPath` 仍是拼接后 `GetBasePath()`，没有“必须留在上传根目录内”的判断。排序参数与 `Extract(..., true)` 的库行为不在本仓库 |

`LIVE_SMOKE.md` 在本仓库与已抓取的远端分支中都不存在，没有条目可确认或否定。

## 3. 新发现

### CUBE-FILE-102 High — 已登录用户默认可读全部非“仅所有者”附件

`CubeController.ValidateToken`（`NewLife.Cube/Controllers/CubeController.cs` 与 `NewLife.CubeNC/Controllers/CubeController.cs`）对 `Image` 和 `File` 直接返回通过，注释写明细粒度检查在方法内部。

`CheckAttachmentAccess` 的实际规则是：

- `ValidateAttachment == false` 时直接允许。该开关默认 `true`。
- 分类落在 `PublicAttachmentCategories`（默认空）时允许匿名。
- 分享令牌的 Url 等于 `attachment:{id}` 时允许。
- 其余情况要求已登录。
- 只有分类落在 `OwnerOnlyAttachmentCategories`（默认空）时才要求 `CreateUserID` 等于当前用户。
- 不满足上述限制时返回允许。

列表控制器 `AttachmentController` 有 `[DataPermission(null, "CreateUserID={#userId}")]`，列表会被收窄。下载动作不走这个特性。云存储分支还会 `Redirect` 到 `GetUrl` 的结果。本地文件缺失时继续 `Fetch(att.Source)`。

**谁受影响：** 打开了魔方且至少有一个普通登录账号的站点。文件管理开关是否打开无关。

**修复方向：** 下载与列表使用同一套数据权限和租户归属；默认把非公开分类视为仅所有者或具备附件菜单权限的角色；公开分类必须显式配置。外层不要在进入检查前放行。云地址在通过归属检查后再签发。

### CUBE-AUTHZ-101 High — 实体上传动作没有菜单权限

`NewLife.Cube/Common/EntityController2.cs` 的 `UploadFile` 只有 `[HttpPost]`。同文件的新增、修改、删除、导入都标了 `EntityAuthorize`。`UserController.UploadFile` 的注释写明：基类不加特性时，这个端点对未按菜单授权的调用方开放，所以用户头像上传单独补了特性并强制只能改当前用户。

主库 `ControllerBaseX.OnActionExecuting` 会拒绝完全匿名的调用，因此这条路径的门槛是“任意已登录用户”，不是匿名。它不检查 `Insert`/`Update`，也不检查目标实体的 `DataPermission`。扩展名只做黑名单。

`NewLife.CubeNC` 的 `ControllerBaseX` 不拒绝匿名，授权完全取决于动作上有没有 `EntityAuthorizeAttribute`。全库没有把该特性注册成全局过滤器。特性内部关于“魔方区域下所有控制器”的注释，在没有全局注册时不会生效。NC 上每个未标注特性的新动作都是同一类缺口，示例见 `CUBE-DEMO-113`。

**谁受影响：** 使用 `NewLife.Cube` 实体控制器的已登录用户；使用 `NewLife.CubeNC` 且动作未标注授权特性的宿主（`CubeDemoNC`、`CubeSSO`）。

**修复方向：** 给 `UploadFile` 标上与导入相同的权限，并在保存前走 `Valid` / 数据权限。NC 要么全局注册授权过滤器，要么让基类在缺少 `[AllowAnonymous]` 时拒绝匿名。不要只在个别子类上补。

### CUBE-JOB-103 High — 作业调度按数据库中的类型名反射执行

`CUBE-JOB-020` 只描述了 `SqlService`。`JobService.MyJob.Start`（`NewLife.CubeNC/Services/JobService.cs`，由主库 Link）读取 `CronJob.Method`：

- 能解析成 `ICubeJob` 时调用 `Execute(argument)`。
- 否则把最后一个点前面当作类型、后面当作方法，反射静态 `Action<string>` 或实例方法，并把 `Argument` 传进去。

`HttpService` 与 `SqlService` 默认 `Enable = false`，但调度器对每一条 `Enable = true` 的 `CronJob` 都会 `Start`。`ExecuteNow` 只要求作业实体的更新权限。`CubeJobBase` 用 `ToJsonEntity` 反序列化参数，类型由作业类固定，不是请求里的类型名；危险点在方法解析，不在 JSON 类型判别（本仓库未发现 `TypeNameHandling` 或 `BinaryFormatter`）。

`ModuleManager.LoadAll` 还会按 `AppModule.FilePath` 执行 `Assembly.LoadFrom`，再 `Activator.CreateInstance`。这是插件设计，没有签名或路径白名单。

**谁受影响：** 能编辑定时作业或应用模块的账号。默认 SQL/HTTP 作业关闭并不能限制一条被启用的自定义作业行。

**修复方向：** 作业方法只允许启动时扫描到的 `ICubeJob` 白名单。参数只反序列化到该作业声明的参数类型。插件目录固定，拒绝任意路径加载，并要求管理员二次确认。

### CUBE-AUTH-104 High — 外部认证转发口令并绑定已有账号

`ExternalAuthUrl` 默认为空，所以这条路径默认不运行。一旦配置，`TokenService` 在本地登录失败后调用 `ExternalAuthHelper.Validate`。该函数把用户名和口令作为 JSON 发到该 URL，不限制目标地址。

`CreateOrUpdateUser` 先按用户名，再按手机、邮箱查找本地用户；找到则覆盖显示名、邮箱、手机、头像、代码。响应里的 `roleName` 若能 `Role.FindByName` 命中，就写入 `RoleID`。这里不会新建角色，这一点弱于 `CUBE-AUTH-003`，但同名已有角色会生效。

**谁受影响：** 配置了外部认证地址的 OAuth 密码模式部署。口令会离开本进程。

**修复方向：** 默认保持关闭。只允许预先登记的 HTTPS 主机。外部系统只返回不可变主体标识，不要用手机、邮箱自动绑定，不要按角色显示名写 `RoleID`。日志和追踪里不要出现口令。

### CUBE-SCOPE-106 Medium — 宿主把实体层数据范围设为全部

`DataScopeMiddleware.CreateHostScope` 固定 `DataScope = DataScopes.全部`，注释说明这是为了让 XCode 行级拦截在魔方宿主内休眠，改由控制器特性负责。主库与 NC 的 `UseCube` 都注册了该中间件。

因此：

- 没有 `[DataPermission]` 的控制器不会自动按用户收窄。
- 租户过滤只发生在 `ReadOnlyEntityController2.CreateWhere`，且仅当 `IsTenantSource` 为真。该属性判断的是 `typeof(ITenantScope)`，不是“有 TenantId 列”。
- 管理后台模式（租户 0）在 `CreateWhere` 中明确不加租户条件。`AuthController.SwitchTenant` 只允许系统角色进入 0，这一点是收紧的。
- 影子模式仍按 `CUBE-TENANT-016` 放行。

已看到带 `DataPermission` 的控制器包括用户、部门、附件、参数、令牌、日志、在线用户、OAuth 日志、用户连接、委托。角色、菜单、应用、OAuth 配置、短信、邮件、访问规则、定时作业等没有这个特性；它们是否还被 `ITenantScope` 挡住，取决于实体是否实现该接口。`OAuthConfig` 在本仓库实现了 `ITenantScope`。`User` 的接口在 XCode 中，标为 Needs Verification，不单独升格。

**谁受影响：** 打开多租户，或依赖 XCode 数据权限、但控制器没写特性的部署。

**修复方向：** 对实现租户接口的实体默认加租户条件，管理后台用单独的显式策略，而不是“没有上下文就看全表”。数据权限不要只靠忘记就会失效的特性。影子模式保持有期限，并在配置界面标明它不是隔离。

### CUBE-CSRF-108 Medium — 若干状态变更使用 GET

在 `CUBE-CSRF-007` 的表单缺口之外，这些动作改变状态且没有防伪令牌：

| 符号 | 文件 |
| --- | --- |
| `SsoController.UnBind` | `NewLife.Cube/Controllers/SsoController.cs`（`[HttpGet]`）、NC 同名动作 |
| `SsoController.Logout` | NC 控制器，`[AllowAnonymous]`，会调用注销 |
| `AccessRuleController.Unblock` | 两个主库/NC 控制器；API 版按 `Accept` 含 `text/html` 时当链接用 |
| `IndexController.Index` 的 `TenantId` 查询 | `NewLife.CubeNC/Areas/Admin/Index/IndexController.cs`，已登录且是成员时写租户 Cookie |

API 版 `AuthController.Logout` 是 POST，这一点比 NC 的 GET 注销好。租户切换 API `SwitchTenant` 也是 POST，并限制了管理员与成员关系。

**谁受影响：** 浏览器会自动带上会话的部署。若同时打开 `TokenCookie` 且站点是 HTTPS，`SameSite=None` 会让跨站请求带上服务端 Cookie（见收窄后的 `CUBE-SESS-006`）。前端自己写的 `token` Cookie 另见 `CUBE-SESS-109`。

**修复方向：** 状态变更只用 POST/PUT/DELETE，并启用防伪或自定义头。GET 只做查询。注销和解除绑定不要用导航即可触发的动作。

### CUBE-SESS-109 Medium — 会话标识与前端令牌都可被脚本读取

`RunTimeMiddleware.CreateSession` 在没有 ASP.NET Session 时执行 `Response.Cookies.Append(".Cube.Session", sid)`，没有 `HttpOnly`、`Secure`、`SameSite`。会话标识来自 `Rand.NextString(16)`，也会回落到请求里的令牌。

`packages/api-core/src/token.ts` 的 `CookieTokenStorage` 用 `document.cookie` 写入名为 `token` 的 Cookie，只设置了 `path=/` 和 `SameSite=Lax`，没有 `HttpOnly`（脚本写入本身也不可能是 HttpOnly），`Secure` 也没有。`LocalTokenStorage` 把同一令牌放进 `localStorage`。

**谁受影响：** 使用魔方会话中间件的 MVC 宿主，以及选用 Cookie 或 localStorage 令牌管理器的前端。

**修复方向：** 服务端会话 Cookie 固定 `HttpOnly`、`Secure`、`SameSite=Lax`。访问令牌优先放在内存里，持久化交给服务端 `HttpOnly` Cookie。不要把访问令牌同时放进查询串（`ViewHelper` 仍会生成带 `token` 查询参数的附件地址）。

### CUBE-DB-111 Medium — 数据库列表接口返回连接串

`NewLife.Cube/Areas/Admin/Controllers/DbController.cs` 的 `BuildDatabaseList` 把 `DAL.ConnStrs` 的值放进 `DbItem.ConnStr`。`Index` 把该列表直接作为 JSON 返回。同控制器的 `GetPageDataContextAsync` 故意去掉了连接串，说明作者知道这里敏感，但列表接口没有同样处理。

动作有 `EntityAuthorize(PermissionFlags.Detail)`。连接名来自请求的备份动作会 `DAL.Create(name)`；未知名字是否会打开新连接取决于 XCode，标 Needs Verification，不把备份本身升成已确认问题。

**谁受影响：** 拥有数据库菜单查看权的账号，以及能读到该接口响应或浏览器调试记录的人。

**修复方向：** 接口只返回连接名、类型、版本和备份数量。口令字段不要进入 JSON、日志或 AI 上下文。备份只接受已登记的连接名。

### CUBE-LOG-110 Medium — 配置保存日志记下属性旧值和新值

`ObjectController.WriteLog` 对每个变化的可写属性追加 `名称:旧值=>新值`。配置对象上的口令、密钥、连接串会进入审计日志。这与 `CUBE-LOG-014` 的 OAuth 日志是不同路径。`MicrosoftClient` 还会 `WriteLog` 输出 `id_token` 的声明 JSON。

`AppLog` 实体把 `AccessToken` 与 `RefreshToken` 作为普通字符串列。令牌以可逆形式落在应用日志表，而不只是追踪文本。

**谁受影响：** 会改系统配置、邮件、短信、OAuth 或对象存储设置的部署，以及能读日志表的人。

**修复方向：** 日志对名称含 Password、Secret、Token、连接串的属性只记“已变更”。令牌入库保存哈希。追踪里不要写 `id_token` 全文。

### CUBE-AI-112 Medium — AI 工具在管理员浏览器里执行脚本

`AiController.AiChat` 有 `EntityAuthorize(PermissionFlags.Detail)`，并在实体页再检查目标控制器权限。对话注册了 `run_js`。系统提示要求模型在写操作前向用户说明，代码路径没有单独的用户确认闸门。`BrowserToolService` 把模型给出的脚本经页面检查点发到当前用户的浏览器。

`get_system_info` 返回机器名、操作系统和资源占用，范围限于已登录且能打开 AI 的用户。`NetworkToolService` 的出站请求在 NewLife.AI 包内，本仓库只看到 `registry.AddTools(new NetworkToolService(...))`，标 Needs Verification，不把它写成已确认的服务端请求伪造。

**谁受影响：** 打开 `AISwitch`（需要看配置是否默认开；`GetAiConfig` 只是读开关）并允许用户使用 AI 对话的站点。

**修复方向：** 浏览器写操作必须由用户显式确认后再执行。只读诊断与改页面分开授权。不要把系统提示当作安全边界。

### CUBE-DEMO-113 Medium — 示例宿主有未授权的控制器动作

`CubeDemoNC` 引用 `NewLife.CubeNC`。`AbcController` 继承框架 `Controller` 而不是魔方基类，`Def` 直接 `Class.FindAll`。`StudentController.Call` 没有 `EntityAuthorize`，按选中键读取学生并写日志。NC 基类不强制登录。

`CubeDemo` 的 `TestController` 三个动作都是 `[AllowAnonymous]`，返回固定演示数据，不读库。`CubeSSO` 的 `UserListController` 继承只读用户控制器并隐藏了口令等列，但仍是用户实体列表，且没有 `DataPermission`。菜单可见性为假，能否打开取决于菜单授权数据。

**谁受影响：** 把示例项目直接部署出去的环境。它们不是库的默认站点，但是本仓库里的可运行宿主。

**修复方向：** 示例要么不要注册到生产路由，要么与正式控制器使用同一授权基类。演示查询不要绕过实体控制器。

### CUBE-OAUTH-117 Medium — 默认 OAuth 访问地址把客户端密钥放在查询串

`OAuthClient` 以及微博、QQ、百度、支付宝、淘宝等客户端的默认 `AccessUrl` 包含 `client_secret={secret}`。`OAuth配置.Biz` 在访问地址为空时也填入同样的查询串模板。密钥会出现在出站 URL 中，进而进入对方访问日志、本机 HTTP 日志和错误信息。

**谁受影响：** 使用这些默认模板、且没有改成 POST 表单的 OAuth 客户端配置。

**修复方向：** 密钥放在请求体或 `Authorization` 头。模板不要把 `{secret}` 编进 URL。已保存的配置需要迁移，改默认值不会改旧数据。

### CUBE-INFO-114 Low — 匿名元数据与未按角色裁剪的菜单

`ReadOnlyEntityController.GetPage` 与 `GetFields`、`ObjectController.GetFields` 标记了 `[AllowAnonymous]`，返回页面设置、字段结构和 `develop` / `isSystem` 标志。`CubeController.Lookup` 按类型名反射枚举。这些不返回业务行，但暴露后台形状。

`NewLife.Cube/Areas/Admin/Controllers/IndexController.GetMenu` 在 `[EntityAuthorize]`（默认权限标志）之后返回菜单树，没有 `CubeController.BuildMenuTree` 里那套角色过滤。`Has(menu, PermissionFlags.None)` 的含义在 XCode，谁能调用此动作标 Needs Verification；树本身未按角色裁剪是本仓库可见的事实。

**修复方向：** 元数据要求登录。菜单树与 `CubeController.MenuTree` 使用同一过滤函数。

### CUBE-CI-116 Info — CI 与包脚本

已读：

- `.github/workflows/test.yml`：全分支 push 与 pull request 上 `dotnet build` / `dotnet test`，没有 `permissions`，动作使用浮动大版本标签。
- `.github/workflows/publish.yml`、`publish-beta.yml`：标签或手动触发时用 `secrets.nugetKey` 推送。没有环境审批，也没有把 NuGet 审计打开。
- `.github/workflows/publish-npm.yml`：`permissions` 为 `contents: read` 与 `packages: write`。`on.push` 写成了序列而不是映射，按 GitHub Actions 的模式这不像有效触发器，工作流可能无法按注释运行。发布步骤把令牌写入用户级 npmrc，这是常见写法，日志级别若打开命令回显会碰到令牌文件。
- 根 `package.json` 的脚本是 `pnpm` 过滤构建与 `dotnet build/run`，没有安装后脚本，没有发现从网络拉脚本再执行的条目。未逐个打开 18 个前端 `package.json` 的 `scripts` 正文。

**修复方向：** 给 CI 显式最小 `permissions`。动作锁定到提交号。修正 npm 工作流的 `on` 结构。审计失败用基线豁免，而不是全局 `NuGetAudit=false`。

## 4. Needs Verification

| 编号 | 内容 | 原因 |
| --- | --- | --- |
| CUBE-TENANT-107 | 示例 `Student` / `Class` / `Trade` 声明 `ITenantSource`，过滤判断的是 `ITenantScope` | 两个接口是否为继承关系在 XCode。若不是，示例数据在打开多租户后不会进入 `CreateWhere` 的租户条件 |
| CUBE-SQL-027 | 列表 `Sort` 仍从查询参数进入 `Pager`，再交给 `FindAll` | 列名是否拼进 SQL 在 XCode。本轮确认调用链还在，不升级 |
| CUBE-ZIP-028 | `FileController.Decompress` 仍调用带覆盖参数的解压 | 路径检查在 NewLife 压缩扩展内 |
| CUBE-NET-119 | `AiController` 注册的 `NetworkToolService`，以及 `CubeFileStorage` 继承的星尘 `DefaultFileStorage` | 出站目标与对端认证不在本仓库。`FileStorageProvide` 与 `FileStorageFetch` 默认 `true`，只说明开关是开的 |

`LocalAttachmentStorage` 维持 `CUBE-STORE-026`，本轮仍未把每条 `FilePath` 调用链追到外部输入，不升级。

## 5. 覆盖范围

属性清点覆盖了 `NewLife.Cube`、`NewLife.CubeNC`、`CubeDemo`、`CubeDemoNC`、`CubeSSO`、`NewLife.Cube.Metronic8` 中文件名含 Controller 的源文件，标出带 `HttpPost`/`Put`/`Delete`/`Patch` 或 `AllowAnonymous` 的公开方法。下面“已读”表示打开并阅读了安全相关段落，不是逐行通读整个文件。

### 5.1 授权与状态变更

已读：两个 `EntityAuthorizeAttribute`、两个 `ControllerBaseX`、两个 `CubeService` 的服务注册与管道（确认没有全局授权过滤器）、`EntityController` / `EntityController2` / `ObjectController` / `ConfigController`、`ReadOnlyEntityController` 的列表与 `GetPage`、`AuthController.SwitchTenant` 与 `Logout`、`SsoController` 的 `Bind`/`UnBind`/`Logout` 段落、`WidgetController`（两个）、`AccessRuleController.Unblock`、`UserController` 头像上传注释、`AiController.AiChat` 前半、`CronJobController.ExecuteNow`、示例 `AbcController`、`StudentController`、`TestController`、`UserListController`。

未完成：每个 OAuth 提供商客户端的登录往返、每个主题控制器、`MfaController` 的全部动作、`LovController` 的数据代理调用细节、NC `ReadOnlyEntityController` 导出动作（第一轮已覆盖令牌）、`Doc/ModelController.cs` 示例。

### 5.2 租户与数据过滤

已读：`DataScopeMiddleware`、`ReadOnlyEntityController2.CreateWhere` 与 `Valid`、`DataPermissionAttribute`、`AuthController.SwitchTenant`、NC 首页的 `TenantId` 查询、`OAuth配置.Biz` 的接口声明、示例实体类声明。

未完成：`Tenant` / `TenantUser` / `Role` 控制器的全部查询重载，`TenantAccessPolicy` 的完整成员判断，XCode 里 `User`、`Department` 是否实现 `ITenantScope`。

### 5.3 文件与附件

已读：两个 `FileController` 的根目录与越界前缀（前 120 行加动作清点）、`AttachmentController`、`LocalAttachmentStorage`、`CubeController` 的 `Image`/`File`/`CheckAttachmentAccess`/`Avatar`、`FileStorageService` / `CubeFileStorage`、`EntityController2.UploadFile` 与扩展名黑名单。

未完成：`FileController` 后半每个动作的字节处理、对象存储签名（`S3ObjectStorage`）、附件 `BuildFilePath` 的全部分支、所有皮肤里的上传表单。

### 5.4 作业、脚本与插件

已读：`HttpService`、`SqlService`、`CubeJobBase`、`JobService` 全文、`ModuleManager.LoadAll`、`CronJobController.ExecuteNow`、`IndexController` 两个重启实现（NC 为 `Process.Start` 当前进程文件名，API 为改 `web.config` 时间）。

未完成：`BackupDbService`、`AttachmentCleanJob`、AI 定时作业正文、`WidgetManager` 的参数写入细节。

### 5.5 出站 HTTP 与反序列化

已读：`DefaultLovListDataProxy.FetchAsync`、`ExternalAuthHelper`、`HttpService`、`OAuthClient` 默认 URL 模板、`TokenService` 口令分支、`CubeJobBase.ToJsonEntity`、`RequestHelper.GetRequestBody` 的 `ToJsonEntity` 调用点。

未完成：每个 `Web/OAuth/*Client.cs` 的请求构造（只检索了密钥是否出现在 URL）、`QyWeiXin` 的部门同步、`SsoClient`、阿里云短信客户端。未在本仓库发现 `BinaryFormatter` 或 Newtonsoft `TypeNameHandling`。`ToJsonEntity` 是否允许类型判别在 NewLife.Core，标 Needs Verification，不单列已确认问题。

### 5.6 配置默认、秘密与日志

已读：`Setting.cs` 中 `Debug`、`TokenCookie`、`ValidateAttachment`、`ExternalAuthUrl`、`FileStorage*`、`SsoSafeDomains` 的默认值，两个示例 `appsettings.json`，`SwaggerService` 默认口令（第一轮已记录，本轮只确认仍在检索结果中）、`ObjectController.WriteLog`、`SsoController` 与 `TokenService` 的日志字符串、`DbController.Index`。

未完成：`Setting.cs` 其余每一项、邮件与短信配置实体的存储字段、`PasswordService` 全文。

### 5.7 CI 与包脚本

已读：四份工作流、`Directory.Build.props`、根 `package.json`、`packages/api-core/src/token.ts`。

未完成：18 个前端包的 `scripts` 逐项、`pnpm-lock.yaml`、Dependabot 配置是否生效。

### 5.8 中间件

已读：`DataScopeMiddleware`、`RunTimeMiddleware.CreateSession` 段落。主库与 NC 的 `UseCube` 中间件注册顺序。

未完成：`TracerMiddleware`、`ApiPrefixRewriteMiddleware`、`RunTimeMiddleware` 前半的运行时间页是否把 SQL 回给浏览器（看到 SQL 文本会 HTML 编码，未追完整开关）。

## 6. 建议的处理顺序

1. 收紧附件下载，使它和附件列表使用同一权限（`CUBE-FILE-102`）。
2. 给 `UploadFile` 补上实体权限，并让 NC 基类默认要求登录（`CUBE-AUTHZ-101`、`CUBE-DEMO-113`）。
3. 作业与插件改为白名单，不要按库存类型名反射（`CUBE-JOB-103`）。
4. 外部认证默认关闭，并禁止按手机、邮箱、角色名接管账号（`CUBE-AUTH-104`）。仍应先处理第一轮的 `CUBE-AUTH-001`。
5. 多租户不要依赖“忘记特性就看全表”；影子模式不要当成隔离（`CUBE-SCOPE-106`，以及已确认的 `CUBE-TENANT-016`）。
6. 状态变更改为带防伪的 POST；服务端 Cookie 与前端令牌分开存放（`CUBE-CSRF-108`、`CUBE-SESS-109`）。
7. 连接串、配置差异、OAuth 密钥退出 JSON、日志和 URL（`CUBE-DB-111`、`CUBE-LOG-110`、`CUBE-OAUTH-117`）。

## 7. 残余风险

静态阅读不能说明现网数据库里 `OwnerOnlyAttachmentCategories`、`ExternalAuthUrl`、`TokenCookie` 或某条 `CronJob` 是否已经被改过。代码默认值只决定新配置。XCode 与 NewLife.Core 里的接口继承、排序 SQL、JSON 类型处理和压缩路径仍需要在依赖源码上另查。本轮没有运行示例，也没有对照真实 HTTP 响应。
