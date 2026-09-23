using System;
using System.ComponentModel;
using System.IO;
using NewLife.Caching;
using NewLife.Cube;
using NewLife.Cube.Entity;
using NewLife.Cube.Models;
using NewLife.Cube.Security;
using NewLife.Cube.Services;
using NewLife.Log;
using XCode.DataAccessLayer;
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
}
