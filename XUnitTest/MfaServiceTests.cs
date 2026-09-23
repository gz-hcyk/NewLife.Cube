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

/// <summary>MFA 门闸逻辑测试（SQLite）</summary>
public class MfaServiceTests
{
    static MfaServiceTests()
    {
        var conn = $"Data Source={Path.GetTempFileName()};Cache=Shared";
        DAL.AddConnStr("Cube", conn, null, "SQLite");
        DAL.AddConnStr("Membership", conn, null, "SQLite");
        DAL.AddConnStr("Log", conn, null, "SQLite");
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
        CubeSetting.Current.JwtSecret = "HS256:test-secret-key-for-mfa";
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
        // secret is now protected; verify via challenge using fresh code from same secret before protect... 
        // After confirm, secret is encrypted — ComputeCode with original setup.Secret still works for VerifyTotp via Unprotect.
        var (verified, remember) = svc.VerifyChallenge(new VerifyMfaModel
        {
            MfaToken = challenge.MfaToken,
            Method = "totp",
            Code = totpCode,
        }, "127.0.0.1");
        Assert.Equal(user.ID, verified.ID);
        Assert.False(remember);
    }
}
