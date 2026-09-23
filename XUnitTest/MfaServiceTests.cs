using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using NewLife.Caching;
using NewLife.Cube;
using NewLife.Cube.Entity;
using NewLife.Cube.Models;
using NewLife.Cube.Security;
using NewLife.Cube.Services;
using NewLife.Log;
using NewLife.Serialization;
using XCode.DataAccessLayer;
using XCode.Membership;
using Xunit;

namespace XUnitTest;

/// <summary>MFA 门闸与安全回归测试（SQLite）</summary>
public class MfaServiceTests
{
    static MfaServiceTests()
    {
        var conn = $"Data Source={Path.GetTempFileName()};Cache=Shared";
        DAL.AddConnStr("Cube", conn, null, "SQLite");
        DAL.AddConnStr("Membership", conn, null, "SQLite");
        DAL.AddConnStr("Log", conn, null, "SQLite");
        CubeSetting.Current.JwtSecret = "HS256:test-secret-key-for-mfa-audit";
        CubeSetting.Current.MfaProtectionKey = "test-mfa-protection-key-32chars!!";
    }

    private static MfaService CreateService()
    {
        var cache = new MemoryCache();
        var provider = new CacheProvider { Cache = cache, InnerCache = cache };
        return new MfaService(provider, new SmsService(provider), new MailService(provider), DefaultTracer.Instance);
    }

    [Fact]
    [DisplayName("EvaluateAfterPassword_关闭EnableMfa_无需挑战")]
    public void Evaluate_WhenMfaDisabled_NoChallenge()
    {
        CubeSetting.Current.EnableMfa = false;
        var svc = CreateService();
        var user = new XCode.Membership.User { ID = 1, Name = "u1", Enable = true };
        var (needChallenge, needBind, _) = svc.EvaluateAfterPassword(user);
        Assert.False(needChallenge);
        Assert.False(needBind);
    }

    [Fact]
    [DisplayName("EvaluateAfterPassword_已绑定TOTP_需要挑战")]
    public void Evaluate_WhenTotpBound_NeedsChallenge()
    {
        CubeSetting.Current.EnableMfa = true;
        CubeSetting.Current.MfaRequired = false;
        var svc = CreateService();

        var user = new XCode.Membership.User
        {
            Name = "mfa_user_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();

        var mfa = UserMfa.GetOrCreate(user.ID);
        mfa.Enable = true;
        mfa.TotpConfirmed = true;
        mfa.TotpSecret = "encrypted";
        mfa.Update();

        var (needChallenge, needBind, _) = svc.EvaluateAfterPassword(user);
        Assert.True(needChallenge);
        Assert.False(needBind);
    }

    [Fact]
    [DisplayName("Totp绑定确认_可用验证码登录挑战")]
    public void TotpConfirm_ThenVerifyChallenge()
    {
        CubeSetting.Current.EnableMfa = true;
        CubeSetting.Current.MaxLoginError = 5;
        var svc = CreateService();

        var user = new XCode.Membership.User
        {
            Name = "mfa_bind_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();

        var setup = svc.StartTotpSetup(user);
        var code = Totp.ComputeCode(setup.Secret);
        var backups = svc.ConfirmTotpSetup(user, code, "127.0.0.1");
        Assert.Equal(8, backups.Length);

        var challenge = svc.CreateChallenge(user, false);
        Assert.Contains("totp", challenge.Methods);
        Assert.Contains("backup", challenge.Methods);

        var totpCode = Totp.ComputeCode(setup.Secret);
        var (verified, remember) = svc.VerifyChallenge(new VerifyMfaModel
        {
            MfaToken = challenge.MfaToken,
            Method = "totp",
            Code = totpCode,
        }, "127.0.0.1");
        Assert.Equal(user.ID, verified.ID);
        Assert.False(remember);
    }

    [Fact]
    [DisplayName("ST-01_挑战令牌不可用于TOTP绑定解析")]
    public void ChallengeToken_CannotResolveForSetup()
    {
        CubeSetting.Current.EnableMfa = true;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_chal_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();

        var setup = svc.StartTotpSetup(user);
        svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");
        var challenge = svc.CreateChallenge(user, false);

        Assert.Throws<InvalidOperationException>(() =>
            svc.ResolveTokenUser(challenge.MfaToken, requireSetup: true));
    }

    [Fact]
    [DisplayName("ST-03_MFA连续失败达到阈值_作废挑战")]
    public void VerifyChallenge_TooManyFailures_ConsumesToken()
    {
        CubeSetting.Current.EnableMfa = true;
        CubeSetting.Current.MaxLoginError = 3;
        CubeSetting.Current.LoginForbiddenTime = 300;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_fail_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();
        var setup = svc.StartTotpSetup(user);
        svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");
        var challenge = svc.CreateChallenge(user, false);

        for (var i = 0; i < 3; i++)
        {
            Assert.Throws<InvalidOperationException>(() => svc.VerifyChallenge(new VerifyMfaModel
            {
                MfaToken = challenge.MfaToken,
                Method = "totp",
                Code = "000000",
            }, "10.0.0.9"));
        }

        Assert.Null(svc.GetChallenge(challenge.MfaToken));
    }

    [Fact]
    [DisplayName("已绑定TOTP_无确认不可重新开始绑定")]
    public void RebindTotp_RequiresConfirm()
    {
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_rebind_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();
        var setup = svc.StartTotpSetup(user);
        svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");

        Assert.Throws<InvalidOperationException>(() => svc.StartTotpSetup(user));
    }

    [Fact]
    [DisplayName("EvaluateAfterLogin_SSO已绑定用户_需要挑战")]
    public void EvaluateAfterLogin_SsoBoundUser_NeedsChallenge()
    {
        CubeSetting.Current.EnableMfa = true;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_sso_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();
        var setup = svc.StartTotpSetup(user);
        svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");

        var (needChallenge, needBind, _) = svc.EvaluateAfterLogin(user);
        Assert.True(needChallenge);
        Assert.False(needBind);
    }

    [Fact]
    [DisplayName("ST-04_EvaluateAfterLogin_短信邮件登录与密码SSO共用判定")]
    public void EvaluateAfterLogin_SharedBySmsMailPasswordSso()
    {
        // LoginBySms/LoginByMail/LoginByPassword/SSO 均经 FinishLoginOrMfa → EvaluateAfterLogin
        CubeSetting.Current.EnableMfa = true;
        CubeSetting.Current.MfaRequired = false;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_sms_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
            Mobile = "13800138000",
            MobileVerified = true,
        };
        user.Insert();

        var (c0, b0, _) = svc.EvaluateAfterLogin(user);
        Assert.False(c0);
        Assert.False(b0);

        var setup = svc.StartTotpSetup(user);
        svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");

        var (needChallenge, needBind, _) = svc.EvaluateAfterLogin(user);
        Assert.True(needChallenge);
        Assert.False(needBind);

        // 与 EvaluateAfterPassword 别名一致，防止短信路径误用旁路 API
        var (c2, b2, _) = svc.EvaluateAfterPassword(user);
        Assert.Equal(needChallenge, c2);
        Assert.Equal(needBind, b2);
    }

    [Fact]
    [DisplayName("ST-通道启停须二次确认")]
    public void SetChannel_RequiresConfirm()
    {
        CubeSetting.Current.EnableMfa = true;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_ch_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
            Mobile = "13900139000",
            MobileVerified = true,
            Password = "Passw0rd!",
        };
        user.Insert();

        Assert.ThrowsAny<Exception>(() => svc.SetChannel(user, "sms", true, null, null, "127.0.0.1"));
        Assert.ThrowsAny<Exception>(() => svc.SetChannel(user, "sms", true, "password", "wrong", "127.0.0.1"));
    }

    [Fact]
    [DisplayName("ST-恢复码v2加盐哈希可校验且一次性消费")]
    public void BackupCode_V2SaltedHash_ConsumesOnce()
    {
        CubeSetting.Current.EnableMfa = true;
        var svc = CreateService();
        var user = new XCode.Membership.User
        {
            Name = "mfa_bk_" + Guid.NewGuid().ToString("N")[..8],
            Enable = true,
        };
        user.Insert();
        var setup = svc.StartTotpSetup(user);
        var codes = svc.ConfirmTotpSetup(user, Totp.ComputeCode(setup.Secret), "127.0.0.1");
        Assert.Equal(8, codes.Length);
        Assert.Contains('-', codes[0]);
        Assert.True(codes[0].Replace("-", "").Length >= 16);

        var mfa = UserMfa.FindByUserId(user.ID);
        Assert.StartsWith("v2:", mfa.BackupCodes.ToJsonEntity<List<String>>()[0]);

        var challenge = svc.CreateChallenge(user, false);
        var (verified, _) = svc.VerifyChallenge(new VerifyMfaModel
        {
            MfaToken = challenge.MfaToken,
            Method = "backup",
            Code = codes[0],
        }, "127.0.0.1");
        Assert.Equal(user.ID, verified.ID);

        var challenge2 = svc.CreateChallenge(user, false);
        Assert.Throws<InvalidOperationException>(() => svc.VerifyChallenge(new VerifyMfaModel
        {
            MfaToken = challenge2.MfaToken,
            Method = "backup",
            Code = codes[0],
        }, "127.0.0.1"));
    }
}
