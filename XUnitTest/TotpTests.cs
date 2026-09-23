using System;
using System.ComponentModel;
using NewLife.Cube.Security;
using Xunit;

namespace XUnitTest;

/// <summary>TOTP 单元测试</summary>
public class TotpTests
{
    [Fact]
    [DisplayName("GenerateSecret_返回有效Base32")]
    public void GenerateSecret_ReturnsValidBase32()
    {
        var secret = Totp.GenerateSecret();
        Assert.False(String.IsNullOrEmpty(secret));
        var bytes = Totp.FromBase32(secret);
        Assert.Equal(20, bytes.Length);
    }

    [Fact]
    [DisplayName("ComputeAndVerify_当前时间窗_通过")]
    public void ComputeAndVerify_CurrentWindow_Succeeds()
    {
        var secret = Totp.GenerateSecret();
        var code = Totp.ComputeCode(secret);
        Assert.Equal(6, code.Length);
        Assert.True(Totp.Verify(secret, code));
    }

    [Fact]
    [DisplayName("Verify_错误码_失败")]
    public void Verify_WrongCode_Fails()
    {
        var secret = Totp.GenerateSecret();
        Assert.False(Totp.Verify(secret, "000000"));
    }

    [Fact]
    [DisplayName("BuildOtpAuthUri_包含issuer与secret")]
    public void BuildOtpAuthUri_ContainsIssuerAndSecret()
    {
        var uri = Totp.BuildOtpAuthUri("Cube", "admin", "JBSWY3DPEHPK3PXP");
        Assert.StartsWith("otpauth://totp/", uri);
        Assert.Contains("secret=JBSWY3DPEHPK3PXP", uri);
        Assert.Contains("issuer=Cube", uri);
    }

    [Fact]
    [DisplayName("Base32_往返一致")]
    public void Base32_RoundTrip()
    {
        var raw = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
        var encoded = Totp.ToBase32(raw);
        var decoded = Totp.FromBase32(encoded);
        Assert.Equal(raw, decoded);
    }
}
