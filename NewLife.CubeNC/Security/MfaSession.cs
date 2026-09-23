using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using SameSiteMode = Microsoft.AspNetCore.Http.SameSiteMode;
using AspNetHttpContext = Microsoft.AspNetCore.Http.HttpContext;

namespace NewLife.Cube.Security;

/// <summary>MFA 相关 Cookie：挑战令牌（避免 URL 泄露）与「已满足 MFA」会话戳</summary>
public static class MfaSession
{
    /// <summary>短期挑战/绑定令牌 Cookie 名</summary>
    public const String TokenCookieName = "Cube.MfaToken";

    /// <summary>本会话已通过 MFA 策略的标记 Cookie</summary>
    public const String SatisfiedCookieName = "Cube.MfaOk";

    /// <summary>将挑战令牌写入 HttpOnly Cookie，避免出现在 URL/Referer</summary>
    public static void WriteChallengeToken(AspNetHttpContext httpContext, String token, Int32 expireSeconds)
    {
        if (httpContext == null || token.IsNullOrEmpty()) return;
        if (expireSeconds <= 0) expireSeconds = 300;

        httpContext.Response.Cookies.Append(TokenCookieName, token, new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax,
            Secure = httpContext.Request.IsHttps,
            MaxAge = TimeSpan.FromSeconds(expireSeconds),
            Path = "/",
        });
    }

    /// <summary>读取挑战令牌（优先查询串，其次 Cookie）</summary>
    public static String ReadChallengeToken(AspNetHttpContext httpContext, String queryToken = null)
    {
        if (!queryToken.IsNullOrEmpty()) return queryToken;
        if (httpContext?.Request.Cookies.TryGetValue(TokenCookieName, out var cookie) == true && !cookie.IsNullOrEmpty())
            return cookie;
        return null;
    }

    /// <summary>清除挑战令牌 Cookie</summary>
    public static void ClearChallengeToken(AspNetHttpContext httpContext)
    {
        httpContext?.Response.Cookies.Delete(TokenCookieName, new CookieOptions { Path = "/" });
    }

    /// <summary>登录完成且满足 MFA 策略后写入会话戳</summary>
    public static void WriteSatisfied(AspNetHttpContext httpContext, Int32 userId, TimeSpan expire)
    {
        if (httpContext == null || userId <= 0) return;

        var value = SignSatisfied(userId);
        var opts = new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax,
            Secure = httpContext.Request.IsHttps,
            Path = "/",
        };
        if (expire > TimeSpan.Zero) opts.MaxAge = expire;
        httpContext.Response.Cookies.Append(SatisfiedCookieName, value, opts);
    }

    /// <summary>校验会话戳是否匹配当前用户</summary>
    public static Boolean IsSatisfied(AspNetHttpContext httpContext, Int32 userId)
    {
        if (httpContext == null || userId <= 0) return false;
        if (!httpContext.Request.Cookies.TryGetValue(SatisfiedCookieName, out var cookie) || cookie.IsNullOrEmpty())
            return false;
        return FixedEqual(cookie, SignSatisfied(userId));
    }

    /// <summary>注销时清除 MFA 会话戳</summary>
    public static void ClearSatisfied(AspNetHttpContext httpContext)
    {
        httpContext?.Response.Cookies.Delete(SatisfiedCookieName, new CookieOptions { Path = "/" });
    }

    private static String SignSatisfied(Int32 userId)
    {
        var material = CubeSetting.Current.JwtSecret;
        if (material.IsNullOrEmpty()) material = "Cube.MfaOk";
        var key = SHA256.HashData(Encoding.UTF8.GetBytes(material));
        var data = Encoding.UTF8.GetBytes("mfaok:" + userId);
        var mac = HMACSHA256.HashData(key, data);
        return userId + "." + Convert.ToHexString(mac);
    }

    private static Boolean FixedEqual(String a, String b)
    {
        if (a == null || b == null || a.Length != b.Length) return false;
        var ba = Encoding.UTF8.GetBytes(a);
        var bb = Encoding.UTF8.GetBytes(b);
        return CryptographicOperations.FixedTimeEquals(ba, bb);
    }
}
