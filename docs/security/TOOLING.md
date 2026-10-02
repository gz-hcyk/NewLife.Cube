# 安全审计静态检查说明

本次没有启动站点，也没有对任何地址发送登录、越权或注入请求。

## 已做的检查

- 在 `NewLife.Cube`、`NewLife.CubeNC` 中检索认证、授权、CSRF、CORS、Cookie、文件路径、`HttpClient`、反序列化相关 API。
- 未发现 `BinaryFormatter`、`TypeNameHandling`、`NetDataContractSerializer`、`LosFormatter`。
- 用 Python 穷举短信验证码算法在默认长度 4 下的十进制前缀，得到 5044 个互异值。算法对应 `NewLife.Cube/Services/SmsService.cs` 的 `GenerateVerifyCode`，字符范围对应 NewLife.Core `Rand.NextString(length, symbol: true)` 的 ASCII `[32, 127)`。

## 未做的检查

- `dotnet build` 与 `dotnet list package --vulnerable` 未运行。本环境没有 NuGet 全局包缓存，且 `Directory.Build.props` 将 `NuGetAudit` 设为 `false`。
- 未反编译 `NewLife.Core` / `NewLife.XCode`。排序参数与 Zip `Extract` 因此标为 Needs Verification。
- 未做动态验证。修复后建议补的测试：
  - 密码模式拒绝 `md5#` 与空密码账号。
  - 授权码不能第二次兑换，且必须匹配 `client_id`。
  - `Urls` 为空时授权端点拒绝回调；前缀主机不能通过。
  - 登录 Cookie 含 `HttpOnly`，编辑表单没有令牌时 POST 失败。
  - `CaptchaScene = 0` 时风险阈值仍能要求图形验证码。
  - 未配置可信代理时忽略 `X-Forwarded-For`。
