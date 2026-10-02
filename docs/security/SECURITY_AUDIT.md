# NewLife.Cube 安全评估报告

| 项 | 内容 |
| --- | --- |
| 文档名称 | NewLife.Cube 防御性安全评估 |
| 评估对象 | 本 fork：`NewLife.Cube`（MVC / 当前主库）与 `NewLife.CubeNC`（历史 WebAPI 副本，大量源文件互相 Link） |
| 评估日期 | 2026-10-02 |
| 基线 | `master` @ `16e453db` |
| 方法 | 静态代码审阅与模式检索。未对任何在线系统发起请求，未编写利用代码 |
| 范围外 | NewLife.Core / XCode 包内部实现（未 restore，排序字段是否拼进 SQL 标为 Needs Verification）、运行时配置与已部署数据 |

## 1. 执行摘要

魔方在登录失败锁定、文件管理默认关闭、部分回调白名单和租户 Cookie 的 `HttpOnly` 上已经有明确防护。当前最需要处理的问题集中在 **OAuth 密码模式把库存口令哈希当成登录凭证**、**SSO 默认按昵称/手机/邮箱绑定已有账号并套用 IdP 角色名**、**授权码是可枚举的数据库自增 Id**，以及 **会话 Cookie 在 HTTPS 下 `SameSite=None` 且登录表单的防伪令牌被注释掉**。

这些不是通用加固建议。下面每一条都能落到具体文件。默认关闭的能力（短信、文件管理、多租户）仍写成 High：开关一开就会按当前实现生效，而默认值本身偏宽松（OAuth 服务端、自动注册、明文密码、空可信代理列表）。

| 级别 | 数量 | 说明 |
| --- | --- | --- |
| Critical | 1 | 密码模式 `md5#` 直接比对库存哈希；空密码被跳过 |
| High | 11 | 账号绑定/角色提升、授权码与回调、会话与 CSRF、OTP、源 IP、应用密钥当全局令牌、文件管理根目录 |
| Medium | 12 | 开放重定向差异、密钥进日志、调试默认值、SSRF、存储型 XSS、租户影子模式等 |
| Low / Info | 6 | 匿名信息接口、依赖审计关闭、示例连接串、加密组件过时 |
| Needs Verification | 3 | 见文末，未在本仓库内证实 |

## 2. 方法

1. 对照 `魔方.sln` 确认 `NewLife.Cube` 与 `NewLife.CubeNC` 通过 `<Compile Include Link>` 共享 SSO、会员、视图模型与设置。
2. 按认证、授权、注入、上传与路径、反序列化与密码学、仓库内秘密、默认安全配置、NuGet 引用做定向检索。
3. 对短信验证码生成函数按 `Rand.NextString(length, symbol: true)` 的 ASCII 区间 `[32, 127)` 做穷举，统计 4 位截断后的可区分前缀（5044）。`Rand.NextString` 行为取自 NewLife.Core 公开源码，与 `NewLife.Cube.csproj` 中的 `NewLife.Core` 11.19.2026.901 同族。
4. 未执行 `dotnet build` / `dotnet list package --vulnerable`：`Directory.Build.props` 将 `NuGetAudit` 设为 `false`，本环境也未预装 NuGet 包缓存。依赖结论只基于 csproj 中可见的包版本。

## 3. 发现一览

| ID | 级别 | 标题 | 位置 |
| --- | --- | --- | --- |
| CUBE-AUTH-001 | Critical | OAuth 密码模式接受 `md5#` 库存哈希，空密码直接通过 | `NewLife.Cube/Services/Sso/TokenService.cs` |
| CUBE-AUTH-002 | High | SSO 默认按用户名/手机/邮箱/昵称绑定已有本地用户 | `UserBindingService.cs`、`Setting.cs` |
| CUBE-AUTH-003 | High | `UseSsoRole` 按 IdP 给出的角色名占用本地角色 | `UserBindingService.FillRoles` |
| CUBE-OAUTH-004 | High | 授权码是 AppLog 自增 Id，未单次使用，未绑定 client_id | `TokenService.GetToken` |
| CUBE-OAUTH-005 | High | 回调地址白名单可被空列表、前缀和 localhost 绕过 | `应用系统.Biz.cs` `ValidCallback` |
| CUBE-SESS-006 | High | 登录 Cookie 无 HttpOnly；HTTPS 下 SameSite=None | `ManagerProviderHelper.SaveCookie` |
| CUBE-CSRF-007 | High | 新增/编辑表单的 AntiForgery 被注释 | `EditForm.cshtml`、`Form.cshtml` |
| CUBE-OTP-008 | High | 短信 OTP 搜索空间约 5044，校验无失败计数；验证码总开关被短路 | `SmsService.cs`、`VerifyCodeService.cs` |
| CUBE-NET-009 | High | 未配置可信代理时信任全部转发头 | `WebHelper2.GetUserHost` |
| CUBE-AUTHZ-010 | High | 应用 Secret 或空 Url 的 UserToken 可访问 Cube 接口 | `CubeController.ValidateToken` |
| CUBE-FILE-011 | High | 文件管理根目录是进程上一级，上传无类型限制 | `FileController` |
| CUBE-AUTH-012 | Medium | OAuth `state` 未绑定浏览器会话；登录后 `returnUrl` 未做本地地址校验 | `SsoController` |
| CUBE-OAUTH-013 | Medium | MVC 版 `Sso/Verify` 任意重定向，且 access_token 在查询串 | `NewLife.Cube/Controllers/SsoController.cs` |
| CUBE-LOG-014 | Medium | 失败路径把 client_secret、访问令牌写入日志/追踪 | `SsoController`、`TokenService` |
| CUBE-DEF-015 | Medium | 一批安全开关默认偏松 | `CubeSetting` |
| CUBE-TENANT-016 | Medium | 多租户默认 Shadow，无租户上下文不加过滤 | `ReadOnlyEntityController2.CreateWhere` |
| CUBE-SSRF-017 | Medium | 头像、附件抓取和值集代理按配置访问任意 URL | `UserBindingService`、`附件.Biz`、`DefaultLovListDataProxy` |
| CUBE-XSS-018 | Medium | 列表链接与 HTML 字段未经编码输出 | `ListField.GetLink`、`_Form_Html.cshtml` |
| CUBE-TOKEN-019 | Medium | 刷新令牌不校验 client_secret；JWT 密钥仅 16 字符 | `TokenService.RefreshToken`、`CubeSetting.OnLoaded` |
| CUBE-JOB-020 | Medium | 定时作业可执行任意 SQL | `Jobs/SqlService.cs` |
| CUBE-SECRET-021 | Medium | Scalar 文档默认口令；示例配置含 root/root | `SwaggerService`、`CubeDemo/appsettings.json` |
| CUBE-INFO-022 | Low | 匿名暴露程序集版本、接口清单 | `CubeController.Info` / `Apis` |
| CUBE-APP-023 | Low | 未知 client_id 会插入禁用的 App 行 | `OAuthAppService.Auth` |
| CUBE-CRYPTO-024 | Low | 令牌公钥接口仍使用 `DSACryptoServiceProvider` | `SsoController.GetKey` |
| CUBE-DEP-025 | Info | NuGet 漏洞审计被仓库关闭 | `Directory.Build.props` |
| CUBE-STORE-026 | Needs Verification | 附件相对路径未做根目录收敛 | `LocalAttachmentStorage.GetFullPath` |
| CUBE-SQL-027 | Needs Verification | 列表 `Sort` 来自查询串 | `Extensions/Pager.cs`、XCode |
| CUBE-ZIP-028 | Needs Verification | 文件管理解压调用 `Extract(..., true)` | `FileController.Decompress` |

## 4. 详细发现

### CUBE-AUTH-001 Critical — 密码模式把库存哈希当作口令

`EnableOAuthServer` 默认为 `true`。应用只要在 `Scopes` 中包含 `password`，`/Sso/Token` 的 `grant_type=password` 就会走到 `GetAccessTokenByPassword`。

```csharp
if (password.StartsWithIgnoreCase("md5#"))
{
    var pass = password["md5#".Length..];
    user = User.Login(username, u =>
    {
        if (!u.Password.IsNullOrEmpty() && !u.Password.EqualIgnoreCase(pass))
            throw new InvalidOperationException($"密码不正确！");
    });
}
```

位置：`NewLife.Cube/Services/Sso/TokenService.cs` 约 271–278 行。

证据与影响：

- 比较对象是 `u.Password`（库存值），不是对用户输入再做一次哈希。持有数据库、备份或日志中的口令哈希即可通过 `md5#` 前缀完成登录（pass-the-hash）。比较还是忽略大小写的。
- `u.Password` 为空时条件短路，任意 `md5#...` 都不会抛错。`UserController.ClearPassword` 把密码写成 `null`（`NewLife.Cube/Areas/Admin/Controllers/UserController.cs` 约 759–766 行）。被清空密码的账号在密码模式开启后可被直接登录。
- 该通道不经过登录页验证码。`AllowLogin=false` 时这里有拦截，但 `AllowLogin` 默认为 `true`。

修复：

- 删除 `md5#` 分支。口令只走 `PasswordProvider` 的验证函数，空哈希必须失败。
- 密码模式改为可选且默认关闭；保留时要求客户端认证，并套用与登录页相同的失败计数。
- `ClearPassword` 改为写入不可验证的随机哈希，或单独的“必须重置”状态，不要留空。

残余风险：已泄露的历史哈希在修复前仍然有效，修复后应强制相关用户改密并吊销 `UserToken`。

### CUBE-AUTH-002 High — 第三方身份默认绑定到已有本地账号

`CubeSetting` 默认值（`NewLife.Cube/Setting.cs` 约 176–241 行）：

- `AutoRegister = true`
- `ForceBindUser / ForceBindUserCode / ForceBindUserMobile / ForceBindUserMail / ForceBindNickName = true`

`UserBindingService.OnBind` 在自动注册开启时依次用 IdP 返回的用户名、代码、手机、邮箱、昵称查找本地用户。昵称走的是 `User.FindByName(client.NickName)`，也就是登录名，只排除了“微信用户”“欢乐马”。

位置：`NewLife.Cube/Services/Sso/UserBindingService.cs` 约 120–165 行。

影响：社交或企业 IdP 的昵称、手机、邮箱由用户或 IdP 配置控制。这些字段一旦与本地管理员登录名或手机邮箱相同，新的第三方登录会接到已有账号上。随后 `Fill` 还会用 IdP 数据覆盖本地手机、邮箱（同文件约 260–264 行）。

修复：默认关闭昵称绑定和“无验证即绑定”。手机、邮箱只在 IdP 明确声明已验证且本地账号也已验证时绑定。用户名绑定限定在内部 IdP，并要求稳定的主体标识（OpenID/sub），不要用可编辑资料。

残余风险：已经写成 `UserConnect` 的错误绑定需要人工核对，代码默认值改掉不会拆开历史数据。

### CUBE-AUTH-003 High — IdP 角色名直接成为本地角色

`UseSsoRole` 默认为 `true`。`FillRoles` → `GetRole(dic, create: true)` 用 `RoleName` / `RoleNames` 查找本地角色，找不到就 `Insert`。找到同名角色时把 `user.RoleID` 设为该角色，包括已有的高权限角色。

位置：`UserBindingService.cs` 约 382–425、821–833 行。

影响：不可信或被篡改的用户信息声明可以把登录者放进名为“管理员”或其他已授权角色。新建角色本身可能没有菜单，但同名已有角色会立即生效。

修复：默认不要采用 IdP 角色。需要时使用显式映射表，禁止按显示名自动匹配，更不要自动建角色。

### CUBE-OAUTH-004 High — 授权码可枚举且可重复兑换

`SsoServerService.GetResult` 把 `code` 设为 `AppLog.Id`。`GetToken` 的实现是：

```csharp
var log = AppLog.FindById(code.ToLong());
if (log == null) throw new ArgumentOutOfRangeException(nameof(code), "Code无效！");
if (log.UpdateTime.AddMinutes(1) < DateTime.Now) throw new ArgumentOutOfRangeException(nameof(code), "Code已过期！");
log.Action = nameof(GetToken);
log.Update();
return new TokenModel { AccessToken = log.AccessToken, RefreshToken = log.RefreshToken, ... };
```

位置：`NewLife.Cube/Services/Sso/TokenService.cs` 约 110–132 行；发放点在 `SsoServerService.cs` 约 101 行。

证据与影响：

- 授权码是单调整数，不是加密随机数。一分钟窗口内可以扫描邻近 Id。
- 注释写“只可使用一次”，代码只是事后把 `Action` 改成 `GetToken`，兑换前不检查旧值，窗口内可重复取走同一对令牌。
- `GetAccessToken` 不核对 `log` 所属应用是否等于请求的 `client_id`。持有任意一个启用应用的密钥（若 `Secret` 为空，`OAuthAppService.Auth` 会跳过密钥比较）即可兑换其他应用刚发出的码。
- `GetToken` 还会把访问令牌写进日志：`token={2}`。

修复：授权码使用 `RandomNumberGenerator` 生成的高熵值；落库哈希；兑换时原子地要求 `Action` 仍为已发放状态并匹配 `client_id` 与 `redirect_uri`；日志中打码。

残余风险：修复前已发出、尚未过期的码仍然可被抢兑。上线时缩短窗口并作废未兑换记录。

### CUBE-OAUTH-005 High — 回调地址校验过宽

`App.ValidCallback`（`NewLife.Cube/Entity/应用系统.Biz.cs` 约 119–145 行）：

- `Urls` 为空时直接 `return true`，任意回调都被接受。
- 使用 `StartsWithIgnoreCase`，白名单 `https://app.example.com` 会放过 `https://app.example.com.evil.example`。
- `http(s)://localhost` 与 `http(s)://localhost:` 在不含 `@` 时一律放行，不看应用自己的白名单。`http://localhost:80.example` 这类字符串能通过前缀判断（端口是否被浏览器接受取决于解析，不能当作安全边界）。

`SsoServerService.Authorize` 只在这一个函数失败时拒绝。授权码或隐式 token 会跟着回调离开本站。

修复：未配置白名单时拒绝。用绝对 URI 解析后比较 scheme、host、port，路径必须等于登记值或位于登记前缀的目录边界之后。localhost 例外仅允许开发配置显式打开。

### CUBE-SESS-006 High — 会话 Cookie 可被脚本读取，HTTPS 下跨站会带上

`ManagerProviderHelper.SaveCookie`（`NewLife.CubeNC/Membership/ManagerProviderHelper.cs` 约 879–907 行，由 `NewLife.Cube.csproj` Link 进主库）：

- 登录令牌 Cookie 没有 `HttpOnly`。同文件的租户 Cookie 明确写了 `HttpOnly = true`，说明这里是遗漏。
- 请求方案为 https 时设置 `SameSite=None` 且 `Secure=true`，注释目的是跨域可读。
- HTTP 时 `SameSite=Unspecified`，也不设 `Secure`。
- “记住登录”把 JWT 与 Cookie 延长到 365 天（`ManageProvider.cs` 约 104–120 行）。

影响：任意存储型或反射型 XSS 都能读出 `token-{系统名}`。在 HTTPS 部署上，该 Cookie 还会随跨站请求发送，见下一条 CSRF。

修复：登录 Cookie 固定 `HttpOnly`、`Secure`（全站 HTTPS 时）、`SameSite=Lax` 或 `Strict`。跨站 SSO 使用一次性授权码或独立的非会话 Cookie，不要把会话 Cookie 设为 `None`。缩短记住登录的绝对寿命，并支持服务端吊销（已有 `jti` / `UserToken` 可以接上）。

### CUBE-CSRF-007 High — 管理表单没有防伪令牌

`NewLife.CubeNC/Views/Shared/EditForm.cshtml` 第 39 行、`Form.cshtml` 第 35 行：

```cshtml
@*@Html.AntiForgeryToken()*@
```

`ObjectForm.cshtml` 与 layui 副本仍输出令牌，主编辑/新增表单没有。控制器侧也没有看到对应的 `[ValidateAntiForgeryToken]`。再叠加 CUBE-SESS-006 的 `SameSite=None`，HTTPS 上的已登录管理员可被外站页面提交用户、角色、参数等变更。

修复：全局 `AutoValidateAntiforgeryToken` 覆盖状态变更方法；恢复表单令牌；API 使用自定义头加 CORS 白名单，而不是凭 Cookie。

残余风险：纯前端 SPA 若只靠 Cookie，需要单独设计 CSRF 头，不能只在 Razor 表单上补令牌。

### CUBE-OTP-008 High — 短信验证码可被猜中，且默认不要求图形验证码

`SmsService.GenerateVerifyCode`（`NewLife.Cube/Services/SmsService.cs` 约 192–199 行）：

```csharp
var randStr = Rand.NextString(codeLength, true);
var strBytes = randStr.GetBytes();
var joinStr = strBytes.Join("");
var code = joinStr.Cut(codeLength);
```

`NextString(n, true)` 从 ASCII 32–126 取字符。实现把这些字节的十进制拼接后再截到 `codeLength`（默认 4）。对长度 4 穷举首两位字节的十进制前缀，得到 **5044** 个互异字符串，且没有以 `0` 或 `2` 开头的值。邮件验证码走 `RandomNumberGenerator`（`MailService.GenerateVerifyCode`），搜索空间是 `10^4`，仍然偏短。

`ResetBySmsCode` / `ResetByMailCode`（`AuthEnhancedService.cs` 约 597–659 行）只做一次相等比较，没有错误次数上限。发送侧有 IP 5 次/10 分钟和同一号码 60 秒一次的限制，限制不住对已发出验证码的猜测。

`VerifyCodeService.RequireCaptcha` 第 47 行在 `CaptchaScene == 0`（默认值）时直接 `return false`。因此默认情况下 `CaptchaRisk = true` 不会生效，发码、登录、注册都不强制图形验证码。登录另有 5 次失败锁定，OTP 校验没有。

`EnableSms` 默认为 false。短信通道一旦打开，重置密码和验证码登录就暴露在上述搜索空间下。

修复：与邮件一样按位使用 `RandomNumberGenerator`，长度至少 6；校验失败按账号与 IP 计数并作废验证码；去掉 `CaptchaScene == 0` 的提前返回，让风险自适应真正生效；发码场景默认打开图形验证码。

### CUBE-NET-009 High — 客户端 IP 可被请求头伪造

`WebHelper2.GetUserHost`（`NewLife.Cube/Web/WebHelper2.cs` 约 71–88 行）在可信代理列表为空时采用“兼容旧行为”：取 `X-Remote-Ip`、`X-Real-IP`、`X-Forwarded-For` 的第一个值。`TrustedProxies` 默认为空。自动学习只记录内网直连地址，公网直连不会被学习，因此直接暴露在公网的进程会一直信任这些头。

影响：登录锁定、子网封禁、验证码风险分、审计 IP 都可以被换成任意地址，包括内网地址（风险分被降到 0）。安全事件里另有 `GetIpChain` 记录原始头，但访问控制用的是被替换后的值。

修复：公网部署必须配置可信代理；列表为空时只使用连接对端地址，不要默认信任转发头。`X-Remote-Ip` 不应优先于标准转发链。

### CUBE-AUTHZ-010 High — 应用密钥等同全站 API 通行证

`CubeController.ValidateToken`（`NewLife.Cube/Controllers/CubeController.cs` 约 97–145 行）：

- `App.FindBySecret(token)` 命中且应用启用，即视为已登录，没有菜单或 Url 范围。
- `UserToken.Url` 为空时，该用户令牌对当前控制器所有非附件动作有效。
- 令牌还可来自查询串 `Token`，会进入访问日志和 Referer。

`ReadOnlyEntityController`（NC）的 `ValidToken` 同样在 `App.FindBySecret` 成功后跳过用户权限（`NewLife.CubeNC/Common/ReadOnlyEntityController.cs` 约 246–257 行）。`FindBySecret` 使用忽略大小写的比较（`应用系统.Biz.cs` 约 101–108 行）。

影响：一个应用的 Secret 泄露后，不需要用户会话即可调用受 `ValidateToken` 保护的接口。查询串令牌还会二次泄露。

修复：应用密钥只用于换取短期、受众受限的令牌，不能当 Bearer。用户分享令牌必须绑定 Url 与权限，禁止空 Url 全局有效。令牌只接受 `Authorization` 头。密钥比较改为固定时间的原始字节比较。

### CUBE-FILE-011 High — 文件管理以站点上一级为根

`EnableFileManager` 默认为 false，`FileManagerAuthorize` 会在关闭时返回 403，这一点是对的。打开之后：

- `Root => "../".GetCurrentPath()`（`NewLife.Cube/Areas/Admin/Controllers/FileController.cs` 第 25 行，NC 副本第 18 行）。进程当前目录的父目录成为可浏览、下载、删除、压缩的根。发布目录的上一级经常包含 `appsettings`、数据文件和密钥目录。
- 越界检查只保证结果仍在这个过宽的根下面。
- 上传只用 `Path.GetFileName`，没有扩展名或内容白名单。`FileMode.OpenOrCreate` 不截断，较短的新文件会在尾部留下旧字节（约 273 行）。
- 解压调用 `fi.Extract(fi.Directory.FullName, true)`。压缩库是否拒绝 Zip Slip 不在本仓库，见 CUBE-ZIP-028。

修复：根目录改为专用的数据目录，而不是 `../`。即使启用，也与 Web 根和配置目录隔离。上传使用允许列表，并用 `FileMode.Create` 覆盖。解压前规范化每个条目路径。

残余风险：默认关闭，所以未改配置的实例不会暴露接口。已打开文件管理的实例应视为可读写应用父目录。

### CUBE-AUTH-012 Medium — OAuth state 与登录回跳

`SsoController.OnLogin` 把新建 `OAuthLog.Id` 当作 `state` 交给 IdP（`NewLife.Cube/Controllers/SsoController.cs` 约 141–157 行）。`LoginInfo` 只按这个整数取日志，不核对当前浏览器会话。攻击者可以用自己的授权结果把受害者的浏览器登录成攻击者账号（登录 CSRF）。

同文件约 275 行在登录成功后执行 `if (!returnUrl.IsNullOrEmpty()) url = returnUrl`。口令登录页使用了 `Url.IsLocalUrl`（`UserController` 约 311 行），这条 OAuth 回跳没有同样的限制。`returnUrl` 来自发起登录时写入的 `RedirectUri`。

修复：`state` 使用与会话绑定的随机值。回跳只允许相对路径或 `SsoSafeDomains` 中的源。

### CUBE-OAUTH-013 Medium — `Verify` 开放重定向（MVC 与 NC 不一致）

`NewLife.Cube/Controllers/SsoController.cs` 的 `Verify`（约 886–908 行）在校验 `access_token` 并写入登录 Cookie 后，对任意 `redirect_uri` 执行 `Redirect`。令牌来自查询串，浏览器会把带令牌的 URL 放进发往目标站的 Referer。

`NewLife.CubeNC/Controllers/SsoController.cs` 约 840–844 行已有 `IsSafeUrl`。主库 MVC 控制器没有同步这道检查。

修复：把 NC 的安全 URL 判断移植到 `NewLife.Cube/Controllers/SsoController.Verify`，并停止在查询串中接收访问令牌。

### CUBE-LOG-014 Medium — 秘密写入日志

- `Access_Token` 失败时：`XTrace.WriteLine($"... client_secret={client_secret} code={code}")`（`SsoController.cs` 约 670 行）。
- `GetAccessToken` 的异常 span 包含 `client_secret`（`TokenService.cs` 约 226 行）。
- `GetToken` 的信息日志包含 `log.AccessToken`（约 116 行）。
- 令牌解码失败时日志包含原始 token（约 176 行）。

修复：日志只保留 client_id、结果和追踪号。密钥与令牌整段不要出现在日志、span 或异常消息里。

### CUBE-DEF-015 Medium — 不安全默认值

| 设置 | 默认 | 位置 |
| --- | --- | --- |
| `Debug` | `true` | `Setting.cs` |
| `AllowPlainPassword` | `true` | 同上，约 171 行 |
| `AllowRegister` | `true` | 约 176 行 |
| `AutoRegister` | `true` | 约 181 行 |
| `EnableOAuthServer` | `true` | 约 492 行 |
| `CorsOrigins` | DEBUG 编译为 `*` | 约 89–92 行 |
| `CaptchaScene` | `0`（并且会关掉风险验证码） | 约 547 行 |
| `EnableMfa` | `false` | 约 567 行 |

`CubeService` 在 `CorsOrigins == "*"` 时使用 `AllowAnyHeader`、`AllowAnyMethod`、`AllowCredentials` 且 `SetIsOriginAllowed(_ => true)`（`NewLife.CubeNC/CubeService.cs` 约 109–114 行）。这是反射来源并携带凭据的 CORS。Release 默认不设来源，Debug 构建和把 `*` 抄进生产配置的实例会打开它。

修复：生产默认关闭自助注册或至少把新用户限制在无菜单角色；明文密码默认关闭；OAuth 服务端默认关闭；CORS 不允许 `*` 与凭据同时出现；`Debug` 默认 false，异常响应不要回传异常对象（`CubeController.OnActionExecuted` 约 86 行把异常放进 JSON）。

### CUBE-TENANT-016 Medium — 多租户影子模式默认放行

`EnableTenant` 默认为 false。一旦打开，`TenantEnforceMode` 仍默认 `Shadow`。`CreateWhere` 在没有租户上下文时不加租户条件，只打影子日志（`ReadOnlyEntityController2.cs` 约 251–261 行）。租户 Id 还可来自 `X-Tenant`、已废弃的 `X-Tenant-Id` 和查询串 `tenantId`（`ManagerProviderHelper.GetTenantId`）。

影响：处于默认影子模式的多租户部署，缺少租户标记的请求会看到启用多租户之前的全表结果。

修复：新部署使用 `Enforce`。影子模式仅作为有时限的迁移开关，并在文档中标明它不是隔离。

### CUBE-SSRF-017 Medium — 服务端按 URL 拉取远程内容

以下调用都没有协议/地址黑名单（链路本地、元数据地址、内网网段）：

- `UserBindingService.FetchAvatar` 对 `http(s)` URL `DownloadFileAsync`，并可附带 `Authorization: Bearer`（约 621–680 行）。OAuth 配置默认 `FetchAvatar = true`。字段映射里的 `UrlReplace` 还能把地址改写成内网。
- `附件.Fetch` 对调用方传入的 URL 执行 `HttpClient.GetAsync`（`附件.Biz.cs` 约 199–225 行）。
- `DefaultLovListDataProxy.FetchAsync` 按值集配置的 `RequestUrl` 发起 GET/POST（管理端配置的 SSRF）。

修复：只允许预期主机；解析后拒绝私网、链路本地和云元数据地址；限制重定向；头像下载不要把用户访问令牌转到任意主机。

### CUBE-XSS-018 Medium — 未编码的 HTML 输出

- `ListField.GetLink` 把 `url` 直接放进 `href`，`linkName` 编码之后又对整段 HTML 做 `Replace`，实体字段会以原始文本进入属性（`NewLife.CubeNC/ViewModels/ListField.cs` 约 304–315 行）。视图使用 `@Html.Raw(txt)`（`_List_Data.cshtml`）。
- `_Form_Html.cshtml` 第 31 行 `@Html.Raw(entity[field.Name])`。富文本字段会按存储内容执行。
- 登录页 `@Html.Raw(Model.LoginTip)`（`Areas/Admin/Views/User/Login.cshtml` 第 34 行）。登录提示来自配置，未登录用户也会执行其中的标记。

修复：链接的 URL 与文本分别编码，禁止在编码后再次替换进 HTML。富文本使用服务端白名单消毒。登录提示改为编码输出或独立的受控 HTML 片段。

### CUBE-TOKEN-019 Medium — 刷新与 JWT 密钥

- `RefreshToken` 调用 `AppService.Auth(client_id, null, ip)`，不验证客户端密钥（`TokenService.cs` 约 434 行）。机密客户端的刷新令牌被窃后可以不带 Secret 续期。
- `OnLoaded` 在 `JwtSecret` 为空时写入 `HS256:` 加 `Rand.NextString(16)`（`Setting.cs` 约 661–665 行）。16 位字母数字约 95 bit，低于 HS256 建议的 256 bit 密钥。注释已说明多实例应固定配置，但首次启动仍会各自生成并 `Save()`。

修复：刷新要求客户端认证，并轮换/作废旧刷新令牌。JWT 密钥至少 32 字节，由部署注入，不要在首个请求里生成。

### CUBE-JOB-020 Medium — 作业中的任意 SQL

`SqlService.OnExecute` 把参数中的 `Sql` 交给 `DAL.Create(connName).Execute(sql)`（`NewLife.CubeNC/Jobs/SqlService.cs` 约 32–44 行）。作业默认 `Enable = false`，启用后拥有定时作业编辑权的账号可以在配置的连接上执行任意语句。这是设计出来的能力，缺少二次确认和只读连接约束。

修复：默认保持关闭；执行账号使用最小权限；记录语句哈希而不是在界面回显完整结果中的敏感列。

### CUBE-SECRET-021 Medium — 仓库中的默认口令

- `NewLife.Cube.Swagger/SwaggerService.cs` 约 163–164 行：未配置时 Basic 认证用户 `newlife`、密码 `newlife@2026`。Scalar/Swagger JSON 被这道认证挡住，但默认口令是公开的。
- `CubeDemo/appsettings.json` 约 16–18 行：注释中的 MySQL 连接使用 `Uid=root;Pwd=root`。当前生效的是本地 SQLite，注释仍会被复制到真实配置。

修复：没有显式配置时不要启用文档站点，或在启动时生成一次性口令并只打印到受控日志。删掉示例中的口令。

### CUBE-INFO-022 Low — 匿名实例信息

`CubeController.Info` 与 `Apis` 标记了 `[AllowAnonymous]`（约 169–204 行），返回程序集名称、版本、编译时间、操作系统、客户端 IP 以及全部动作签名。

修复：生产环境只保留不含版本的健康检查，接口清单要求登录。

### CUBE-APP-023 Low — 匿名写入应用表

`OAuthAppService.Auth` 在找不到 `client_id` 时 `Insert` 一条新 `App`（约 43–49 行）。新行默认不可用，随后会因未启用被拒绝，但匿名调用方可以占用名称并增加行数。`Authorize` 在登录前就会走到这里。

修复：未知 client_id 直接拒绝，不要插入。

### CUBE-CRYPTO-024 Low — DSA 令牌密钥

`GetKey` 使用 `DSACryptoServiceProvider` 导入 XML 密钥并导出公钥（`SsoController.cs` 约 861–877 行）。该类在现代 .NET 上已过时，密钥长度取决于 `DSAHelper.GenerateKey`（在 NewLife.Core 中，本仓库看不到）。同时 `ExportParameters(true)` 会在内存中展开私钥，虽然没有返回给客户端。

修复：新令牌改用 RSA-2048 或 ECDSA P-256，并停止为了导出公钥而加载私钥参数。

### CUBE-DEP-025 Info — 依赖风险无法在本仓库内核实

`Directory.Build.props` 设置 `<NuGetAudit>false</NuGetAudit>`。直接引用包括：

- `NewLife.Core` 11.19.2026.901
- `NewLife.XCode` 12.2.2026.901
- `NewLife.AI` 1.6.2026.901
- `NewLife.Stardust.Extensions` 3.10.2026.901
- `NewLife.Office` 1.4.2026.901
- `NewLife.IP` 2.5.2026.804
- `Microsoft.SourceLink.GitHub` 1.1.1

本环境没有包缓存，不能给出 CVE 列表。关闭审计本身会让已知漏洞在 CI 中不可见。

修复：CI 打开 `NuGetAudit`，对失败采用基线豁免而不是全局关闭。

### CUBE-STORE-026 Needs Verification — 附件路径

`LocalAttachmentStorage.GetFullPath` 是 `root.CombinePath(filePath).GetBasePath()`，没有“结果必须仍在 root 下”的检查。`附件.BuildFilePath` 多数由分类和 Id 生成。若任何接口把用户提供的 `FilePath` 传进来，就可能写出上传目录之外。本次没有把每条调用链都追到外部输入，因此不升为已确认漏洞。

建议：与文件管理相同，规范化后拒绝跳出根目录。

### CUBE-SQL-027 Needs Verification — 排序参数

`Pager` 从查询参数读取 `Sort`（`NewLife.Cube/Extensions/Pager.cs` 约 114 行），`SearchData` 把 `Pager` 交给 `Entity.FindAll`。列名白名单若只存在于 XCode，本仓库看不到。在未审阅 XCode 12.2.2026.901 之前，不能断定排序参数是否进入 SQL 文本。

### CUBE-ZIP-028 Needs Verification — 解压路径

文件管理 `Decompress` 调用 NewLife 扩展 `Extract(目录, true)`。Zip Slip 是否被库拒绝需要看该包的实现和测试，不在本次已读源码中。

## 5. 已观察到的防护

这些控制是有效的，修复时不要退回去：

- 文件管理有独立开关，默认关闭，关闭时过滤器返回 403。
- 文件管理对解析后的完整路径做了前缀检查；上传丢弃客户端路径，只留文件名。
- 口令登录的 `returnUrl` 使用 `Url.IsLocalUrl`。
- 登录失败有次数、封禁时间和两段/三段子网阈值。
- 密码强度默认要求长度与四类字符；另有可选的挑战应答传输。
- 租户 Cookie 设置了 `HttpOnly`。
- NC 版 `Sso/Verify` 已拒绝非本站重定向；OAuth 服务端在 `EnableOAuthServer=false` 时会拒绝发令牌。
- 刷新令牌与访问令牌使用不同的 Id（`NewLife.CubeNC/Services/TokenService.IssueToken`）。
- 邮件 OTP 使用 `RandomNumberGenerator`。
- `BindAfterLogin` 拒绝把别人的 OAuth 日志绑到当前用户。

## 6. 建议的处理顺序

1. 去掉 `md5#` 登录，并禁止空密码通过（CUBE-AUTH-001）。
2. 收紧 SSO 绑定与角色采用的默认值（002、003）。
3. 换掉可枚举授权码，收紧回调白名单，补上 MVC `Verify` 的 URL 检查（004、005、013）。
4. 登录 Cookie 加 `HttpOnly`，HTTPS 不要用 `SameSite=None`；恢复 AntiForgery（006、007）。
5. 修正短信 OTP 与 `CaptchaScene == 0` 短路；公网部署写上可信代理（008、009）。
6. 应用 Secret 不再作为全局 Bearer；文件管理改根目录（010、011）。

## 7. 残余风险

静态阅读不能证明运行中的数据库里是否已有空 `Secret` 的启用应用、是否已打开文件管理或短信。默认值决定了新安装的行为；已保存的 `Cube` 配置会覆盖代码默认值。XCode 与 NewLife.Core 内部的排序、压缩和 DSA 密钥长度需要在依赖源码上另做一次确认。
