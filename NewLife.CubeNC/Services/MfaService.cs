using System.Security.Cryptography;
using System.Text;
using NewLife;
using NewLife.Caching;
using NewLife.Cube.Entity;
using NewLife.Cube.Models;
using NewLife.Cube.Security;
using NewLife.Log;
using NewLife.Security;
using NewLife.Serialization;
using NewLife.Web;
using XCode.Membership;

namespace NewLife.Cube.Services;

/// <summary>MFA 二步验证服务</summary>
public class MfaService(ICacheProvider cacheProvider, SmsService smsService, MailService mailService, ITracer tracer)
{
    private const String ChallengePrefix = "Mfa:Challenge:";
    private const String PendingTotpPrefix = "Mfa:PendingTotp:";
    private const String SmsCodePrefix = "Mfa:Sms:Code:";
    private const String MailCodePrefix = "Mfa:Mail:Code:";
    private const String SmsLastSendPrefix = "Mfa:Sms:LastSend:";
    private const String MailLastSendPrefix = "Mfa:Mail:LastSend:";
    private const String SmsIpPrefix = "Mfa:Sms:IP:";
    private const String MailIpPrefix = "Mfa:Mail:IP:";

    private readonly ICache _cache = cacheProvider.Cache;

    #region 判定
    /// <summary>密码登录后是否需要 MFA 挑战。needBind 表示强制绑定但未绑定</summary>
    public (Boolean needChallenge, Boolean needBind, UserMfa mfa) EvaluateAfterPassword(User user)
    {
        var set = CubeSetting.Current;
        if (!set.EnableMfa) return (false, false, null);

        var mfa = UserMfa.FindByUserId(user.ID);
        if (mfa != null && mfa.IsActive) return (true, false, mfa);

        if (set.MfaRequired) return (false, true, mfa);
        return (false, false, mfa);
    }

    /// <summary>可用挑战通道</summary>
    public String[] GetMethods(UserMfa mfa, User user)
    {
        var list = new List<String>();
        if (mfa == null) return list.ToArray();

        if (mfa.TotpConfirmed && !mfa.TotpSecret.IsNullOrEmpty()) list.Add("totp");
        if (mfa.SmsEnabled && user != null && !user.Mobile.IsNullOrEmpty() && user.MobileVerified) list.Add("sms");
        if (mfa.MailEnabled && user != null && !user.Mail.IsNullOrEmpty() && user.MailVerified) list.Add("mail");
        if (CountBackupCodes(mfa) > 0) list.Add("backup");
        return list.ToArray();
    }
    #endregion

    #region 挑战令牌
    /// <summary>创建强制绑定用的 setup 会话（无可用 methods）</summary>
    public MfaChallengeModel CreateSetupSession(User user, Boolean remember)
    {
        var set = CubeSetting.Current;
        var token = Rand.NextString(32);
        var expire = set.MfaTokenExpire > 0 ? set.MfaTokenExpire : 300;
        _cache.Set($"{ChallengePrefix}{token}", new MfaChallengeState
        {
            UserId = user.ID,
            Remember = remember,
            IsSetup = true,
        }, expire);

        return new MfaChallengeModel
        {
            MfaToken = token,
            ExpireIn = expire,
            Methods = [],
            DisplayName = user.DisplayName.IsNullOrEmpty() ? user.Name : user.DisplayName,
        };
    }

    /// <summary>根据 setup/challenge 令牌解析用户</summary>
    public (User user, MfaChallengeState state) ResolveTokenUser(String mfaToken, Boolean requireSetup = false)
    {
        var state = GetChallenge(mfaToken);
        if (state == null) throw new InvalidOperationException("会话已过期，请重新登录");
        if (requireSetup && !state.IsSetup) throw new InvalidOperationException("无效的绑定会话");
        var user = User.FindByID(state.UserId) ?? throw new InvalidOperationException("用户不存在");
        return (user, state);
    }

    /// <summary>创建挑战并返回模型（调用方须先 Logout 清除密码登录会话）</summary>
    public MfaChallengeModel CreateChallenge(User user, Boolean remember)
    {
        var set = CubeSetting.Current;
        var mfa = UserMfa.FindByUserId(user.ID) ?? UserMfa.GetOrCreate(user.ID);
        var methods = GetMethods(mfa, user);
        if (methods.Length == 0)
            throw new InvalidOperationException("未配置可用的第二因子通道");

        var token = Rand.NextString(32);
        var expire = set.MfaTokenExpire > 0 ? set.MfaTokenExpire : 300;
        _cache.Set($"{ChallengePrefix}{token}", new MfaChallengeState
        {
            UserId = user.ID,
            Remember = remember,
        }, expire);

        return new MfaChallengeModel
        {
            MfaToken = token,
            ExpireIn = expire,
            Methods = methods,
            DisplayName = user.DisplayName.IsNullOrEmpty() ? user.Name : user.DisplayName,
        };
    }

    /// <summary>读取挑战状态</summary>
    public MfaChallengeState GetChallenge(String mfaToken)
    {
        if (mfaToken.IsNullOrEmpty()) return null;
        return _cache.Get<MfaChallengeState>($"{ChallengePrefix}{mfaToken}");
    }

    /// <summary>作废挑战</summary>
    public void ConsumeChallenge(String mfaToken)
    {
        if (!mfaToken.IsNullOrEmpty()) _cache.Remove($"{ChallengePrefix}{mfaToken}");
    }
    #endregion

    #region 校验第二因子
    /// <summary>校验并返回用户与 Remember（成功后消费挑战令牌）</summary>
    public (User user, Boolean remember) VerifyChallenge(VerifyMfaModel model, String ip)
    {
        using var span = tracer?.NewSpan(nameof(VerifyChallenge), model?.Method);
        var state = GetChallenge(model?.MfaToken);
        if (state == null) throw new InvalidOperationException("挑战已过期，请重新登录");

        var user = User.FindByID(state.UserId);
        if (user == null || !user.Enable) throw new InvalidOperationException("用户不存在或已禁用");

        var mfa = UserMfa.FindByUserId(user.ID);
        if (mfa == null || !mfa.IsActive) throw new InvalidOperationException("用户未启用二步验证");

        var method = (model.Method ?? "").Trim().ToLowerInvariant();
        var code = model.Code?.Trim() ?? "";
        if (code.IsNullOrEmpty()) throw new ArgumentException("验证码不能为空", nameof(model.Code));

        var ok = method switch
        {
            "totp" => VerifyTotp(mfa, code),
            "sms" => VerifySmsCode(user, code),
            "mail" => VerifyMailCode(user, code),
            "backup" => ConsumeBackupCode(mfa, code),
            _ => throw new ArgumentException("不支持的验证通道", nameof(model.Method)),
        };

        if (!ok)
        {
            LogProvider.Provider.WriteLog(typeof(User), "MFA校验", false, $"method={method}", user.ID, user.Name, ip);
            throw new InvalidOperationException("验证码错误");
        }

        var remember = state.Remember;
        ConsumeChallenge(model.MfaToken);
        LogProvider.Provider.WriteLog(typeof(User), "MFA校验", true, $"method={method}", user.ID, user.Name, ip);
        return (user, remember);
    }
    #endregion

    #region 发送 SMS/Mail 挑战码
    /// <summary>向挑战用户发送短信/邮件验证码</summary>
    public async Task SendChallengeCode(SendMfaCodeModel model, String ip)
    {
        var state = GetChallenge(model?.MfaToken);
        if (state == null) throw new InvalidOperationException("挑战已过期，请重新登录");

        var user = User.FindByID(state.UserId) ?? throw new InvalidOperationException("用户不存在");
        var mfa = UserMfa.FindByUserId(user.ID);
        var method = (model.Method ?? "").Trim().ToLowerInvariant();

        if (method == "sms")
        {
            if (mfa == null || !mfa.SmsEnabled) throw new InvalidOperationException("未启用短信第二因子");
            if (user.Mobile.IsNullOrEmpty() || !user.MobileVerified) throw new InvalidOperationException("手机未验证");
            await SendSmsInternal(user, ip);
        }
        else if (method == "mail")
        {
            if (mfa == null || !mfa.MailEnabled) throw new InvalidOperationException("未启用邮件第二因子");
            if (user.Mail.IsNullOrEmpty() || !user.MailVerified) throw new InvalidOperationException("邮箱未验证");
            await SendMailInternal(user, ip);
        }
        else throw new ArgumentException("仅支持 sms/mail", nameof(model.Method));
    }

    private async Task SendSmsInternal(User user, String ip)
    {
        var set = CubeSetting.Current;
        if (!set.EnableSms) throw new XException("短信验证码功能未启用");

        var config = smsService.GetConfig(TenantContext.CurrentId, "login");
        if (config == null) throw new XException("短信服务未配置");

        GuardSendRate($"{SmsIpPrefix}{ip}", $"{SmsLastSendPrefix}{user.Mobile}");

        var code = SmsService.GenerateVerifyCode(config.CodeLength > 0 ? config.CodeLength : 6);
        var rs = await smsService.SendVerifyCode("login", user.Mobile, code, config);
        if (rs == null || !rs.Success) throw new XException("短信发送失败");

        _cache.Set($"{SmsCodePrefix}{user.ID}", code, config.Expire > 0 ? config.Expire : 300);
        _cache.Set($"{SmsLastSendPrefix}{user.Mobile}", DateTime.Now, 60);
    }

    private async Task SendMailInternal(User user, String ip)
    {
        var set = CubeSetting.Current;
        if (!set.EnableMail) throw new XException("邮件验证码功能未启用");

        var config = mailService.GetConfig(TenantContext.CurrentId, "login");
        GuardSendRate($"{MailIpPrefix}{ip}", $"{MailLastSendPrefix}{user.Mail}");

        var code = MailService.GenerateVerifyCode(config != null && config.CodeLength > 0 ? config.CodeLength : 6);
        var rs = await mailService.SendVerifyCode("login", user.Mail, code, config);
        if (rs == null || !rs.Success) throw new XException("邮件发送失败");

        var expire = config?.Expire > 0 ? config.Expire : 300;
        _cache.Set($"{MailCodePrefix}{user.ID}", code, expire);
        _cache.Set($"{MailLastSendPrefix}{user.Mail}", DateTime.Now, 60);
    }

    private void GuardSendRate(String ipKey, String lastKey)
    {
        var ipCount = _cache.Get<Int32>(ipKey);
        if (ipCount >= 5) throw new XException("发送频繁，请稍后再试");

        var lastSend = _cache.Get<DateTime>(lastKey);
        if (lastSend > DateTime.MinValue && (DateTime.Now - lastSend).TotalSeconds < 60)
        {
            var wait = 60 - (Int32)(DateTime.Now - lastSend).TotalSeconds;
            throw new XException($"请{wait}秒后再试");
        }

        _cache.Increment(ipKey, 1);
        if (ipCount <= 0) _cache.SetExpire(ipKey, TimeSpan.FromMinutes(10));
    }

    private Boolean VerifySmsCode(User user, String code)
    {
        var key = $"{SmsCodePrefix}{user.ID}";
        var cached = _cache.Get<String>(key);
        if (cached.IsNullOrEmpty()) return false;
        if (!cached.EqualIgnoreCase(code)) return false;
        _cache.Remove(key);
        return true;
    }

    private Boolean VerifyMailCode(User user, String code)
    {
        var key = $"{MailCodePrefix}{user.ID}";
        var cached = _cache.Get<String>(key);
        if (cached.IsNullOrEmpty()) return false;
        if (!cached.EqualIgnoreCase(code)) return false;
        _cache.Remove(key);
        return true;
    }
    #endregion

    #region TOTP 绑定
    /// <summary>开始绑定 TOTP，返回密钥与 otpauth。user 来自登录用户或 setupToken</summary>
    public TotpSetupModel StartTotpSetup(User user)
    {
        var set = CubeSetting.Current;
        var secret = Totp.GenerateSecret();
        _cache.Set($"{PendingTotpPrefix}{user.ID}", secret, 600);

        var issuer = set.MfaIssuer.IsNullOrEmpty() ? "NewLife.Cube" : set.MfaIssuer;
        var account = user.Name.IsNullOrEmpty() ? user.ID + "" : user.Name;
        return new TotpSetupModel
        {
            Secret = secret,
            Issuer = issuer,
            OtpAuthUri = Totp.BuildOtpAuthUri(issuer, account, secret),
        };
    }

    /// <summary>确认 TOTP 首码并启用；返回一次性明文恢复码</summary>
    public String[] ConfirmTotpSetup(User user, String code, String ip)
    {
        var secret = _cache.Get<String>($"{PendingTotpPrefix}{user.ID}");
        if (secret.IsNullOrEmpty()) throw new InvalidOperationException("绑定会话已过期，请重新开始");
        if (!Totp.Verify(secret, code)) throw new InvalidOperationException("验证码错误");

        var mfa = UserMfa.GetOrCreate(user.ID);
        mfa.TotpSecret = ProtectSecret(secret);
        mfa.TotpConfirmed = true;
        mfa.Enable = true;
        var codes = GenerateBackupCodes(8);
        mfa.BackupCodes = HashBackupCodes(codes).ToJson();
        mfa.Update();

        _cache.Remove($"{PendingTotpPrefix}{user.ID}");
        LogProvider.Provider.WriteLog(typeof(User), "绑定TOTP", true, null, user.ID, user.Name, ip);
        return codes;
    }

    /// <summary>解绑 TOTP</summary>
    public void UnbindTotp(User user, String method, String code, String ip)
    {
        var mfa = UserMfa.FindByUserId(user.ID) ?? throw new InvalidOperationException("未启用 MFA");
        EnsureConfirm(user, mfa, method, code);

        mfa.TotpSecret = null;
        mfa.TotpConfirmed = false;
        if (!mfa.SmsEnabled && !mfa.MailEnabled)
        {
            mfa.Enable = false;
            mfa.BackupCodes = null;
        }
        mfa.Update();
        LogProvider.Provider.WriteLog(typeof(User), "解绑TOTP", true, null, user.ID, user.Name, ip);
    }
    #endregion

    #region 通道 / 启停 / 恢复码
    /// <summary>启停短信/邮件通道</summary>
    public void SetChannel(User user, String channel, Boolean enable, String ip)
    {
        var mfa = UserMfa.GetOrCreate(user.ID);
        channel = (channel ?? "").Trim().ToLowerInvariant();
        if (channel == "sms")
        {
            if (enable && (user.Mobile.IsNullOrEmpty() || !user.MobileVerified))
                throw new InvalidOperationException("请先验证手机号");
            mfa.SmsEnabled = enable;
        }
        else if (channel == "mail")
        {
            if (enable && (user.Mail.IsNullOrEmpty() || !user.MailVerified))
                throw new InvalidOperationException("请先验证邮箱");
            mfa.MailEnabled = enable;
        }
        else throw new ArgumentException("通道仅支持 sms/mail", nameof(channel));

        if (enable)
        {
            mfa.Enable = true;
            if (CountBackupCodes(mfa) == 0)
            {
                var codes = GenerateBackupCodes(8);
                mfa.BackupCodes = HashBackupCodes(codes).ToJson();
                // 恢复码仅在 TOTP 确认或主动生成时展示；此处静默生成哈希
            }
        }
        else if (!mfa.HasBoundFactor)
        {
            mfa.Enable = false;
        }

        mfa.Update();
        LogProvider.Provider.WriteLog(typeof(User), "MFA通道", true, $"{channel}={enable}", user.ID, user.Name, ip);
    }

    /// <summary>关闭用户 MFA</summary>
    public void Disable(User user, String method, String code, String ip)
    {
        var mfa = UserMfa.FindByUserId(user.ID) ?? throw new InvalidOperationException("未启用 MFA");
        EnsureConfirm(user, mfa, method, code);

        mfa.Enable = false;
        mfa.TotpSecret = null;
        mfa.TotpConfirmed = false;
        mfa.SmsEnabled = false;
        mfa.MailEnabled = false;
        mfa.BackupCodes = null;
        mfa.Update();
        LogProvider.Provider.WriteLog(typeof(User), "关闭MFA", true, null, user.ID, user.Name, ip);
    }

    /// <summary>重新生成恢复码（返回明文一次）</summary>
    public String[] RegenerateBackupCodes(User user, String method, String code, String ip)
    {
        var mfa = UserMfa.FindByUserId(user.ID) ?? throw new InvalidOperationException("未启用 MFA");
        if (!mfa.Enable) throw new InvalidOperationException("请先启用 MFA");
        EnsureConfirm(user, mfa, method, code);

        var codes = GenerateBackupCodes(8);
        mfa.BackupCodes = HashBackupCodes(codes).ToJson();
        mfa.Update();
        LogProvider.Provider.WriteLog(typeof(User), "重建恢复码", true, null, user.ID, user.Name, ip);
        return codes;
    }

    /// <summary>状态模型</summary>
    public MfaStatusModel GetStatus(User user)
    {
        var set = CubeSetting.Current;
        var mfa = UserMfa.FindByUserId(user.ID);
        return new MfaStatusModel
        {
            GlobalEnabled = set.EnableMfa,
            Required = set.MfaRequired,
            Enable = mfa?.Enable ?? false,
            TotpConfirmed = mfa?.TotpConfirmed ?? false,
            SmsEnabled = mfa?.SmsEnabled ?? false,
            MailEnabled = mfa?.MailEnabled ?? false,
            MobileMasked = MaskMobile(user.Mobile),
            MailMasked = MaskMail(user.Mail),
            MobileVerified = user.MobileVerified,
            MailVerified = user.MailVerified,
            BackupCodeCount = CountBackupCodes(mfa),
        };
    }
    #endregion

    #region 内部工具
    private Boolean VerifyTotp(UserMfa mfa, String code)
    {
        var secret = UnprotectSecret(mfa.TotpSecret);
        return !secret.IsNullOrEmpty() && Totp.Verify(secret, code);
    }

    private void EnsureConfirm(User user, UserMfa mfa, String method, String code)
    {
        method = (method ?? "totp").Trim().ToLowerInvariant();
        code ??= "";
        if (method == "password")
        {
            var hash = ManageProvider.Provider?.PasswordProvider?.Hash(code);
            if (hash.IsNullOrEmpty() || user.Password != hash)
                throw new InvalidOperationException("密码错误");
            return;
        }

        var ok = method switch
        {
            "totp" => VerifyTotp(mfa, code),
            "sms" => VerifySmsCode(user, code),
            "mail" => VerifyMailCode(user, code),
            "backup" => ConsumeBackupCode(mfa, code),
            _ => false,
        };
        if (!ok) throw new InvalidOperationException("验证失败");
    }

    private static String[] GenerateBackupCodes(Int32 count)
    {
        var list = new String[count];
        for (var i = 0; i < count; i++)
        {
            var raw = Rand.NextString(8).ToUpperInvariant();
            list[i] = $"{raw[..4]}-{raw[4..]}";
        }
        return list;
    }

    private static IList<String> HashBackupCodes(IEnumerable<String> codes) =>
        codes.Select(HashCode).ToList();

    private static String HashCode(String code)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(NormalizeBackup(code)));
        return Convert.ToHexString(bytes);
    }

    private static String NormalizeBackup(String code) =>
        (code ?? "").Replace("-", null).Replace(" ", null).Trim().ToUpperInvariant();

    private Boolean ConsumeBackupCode(UserMfa mfa, String code)
    {
        var hashes = mfa.BackupCodes.ToJsonEntity<List<String>>() ?? [];
        var target = HashCode(code);
        var idx = hashes.FindIndex(e => e.EqualIgnoreCase(target));
        if (idx < 0) return false;
        hashes.RemoveAt(idx);
        mfa.BackupCodes = hashes.ToJson();
        mfa.Update();
        return true;
    }

    private static Int32 CountBackupCodes(UserMfa mfa)
    {
        if (mfa == null || mfa.BackupCodes.IsNullOrEmpty()) return 0;
        var list = mfa.BackupCodes.ToJsonEntity<List<String>>();
        return list?.Count ?? 0;
    }

    private static String ProtectSecret(String plain)
    {
        if (plain.IsNullOrEmpty()) return plain;
        var key = DeriveKey();
        var plainBytes = Encoding.UTF8.GetBytes(plain);
        var iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        using var enc = aes.CreateEncryptor();
        var cipher = enc.TransformFinalBlock(plainBytes, 0, plainBytes.Length);
        return Convert.ToBase64String(iv.Concat(cipher).ToArray());
    }

    private static String UnprotectSecret(String protectedText)
    {
        if (protectedText.IsNullOrEmpty()) return null;
        try
        {
            var all = Convert.FromBase64String(protectedText);
            if (all.Length < 17) return null;
            var iv = all.AsSpan(0, 16).ToArray();
            var cipher = all.AsSpan(16).ToArray();
            using var aes = Aes.Create();
            aes.Key = DeriveKey();
            aes.IV = iv;
            using var dec = aes.CreateDecryptor();
            var plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            // 兼容未加密明文（开发期）
            return protectedText;
        }
    }

    private static Byte[] DeriveKey()
    {
        var material = CubeSetting.Current.JwtSecret;
        if (material.IsNullOrEmpty()) material = "NewLife.Cube.Mfa.DefaultKey";
        return SHA256.HashData(Encoding.UTF8.GetBytes(material));
    }

    private static String MaskMobile(String mobile)
    {
        if (mobile.IsNullOrEmpty() || mobile.Length < 7) return mobile;
        return $"{mobile[..3]}****{mobile[^4..]}";
    }

    private static String MaskMail(String mail)
    {
        if (mail.IsNullOrEmpty()) return mail;
        var at = mail.IndexOf('@');
        if (at <= 1) return "***" + mail;
        return mail[0] + "***" + mail[at..];
    }
    #endregion
}

/// <summary>MFA 挑战缓存态</summary>
public class MfaChallengeState
{
    /// <summary>用户编号</summary>
    public Int32 UserId { get; set; }

    /// <summary>记住登录</summary>
    public Boolean Remember { get; set; }

    /// <summary>是否为强制绑定会话</summary>
    public Boolean IsSetup { get; set; }

    /// <summary>已校验（可选）</summary>
    public Boolean Verified { get; set; }
}
