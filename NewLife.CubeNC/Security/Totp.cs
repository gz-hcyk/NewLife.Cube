using System.Security.Cryptography;
using System.Text;

namespace NewLife.Cube.Security;

/// <summary>RFC 6238 TOTP（基于 HMAC-SHA1，默认 30 秒步长、6 位）</summary>
public static class Totp
{
    private const String Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /// <summary>生成随机 Base32 密钥（默认 20 字节 / 160 bit）</summary>
    public static String GenerateSecret(Int32 bytes = 20)
    {
        var data = new Byte[bytes];
        RandomNumberGenerator.Fill(data);
        return ToBase32(data);
    }

    /// <summary>构造 otpauth URI</summary>
    public static String BuildOtpAuthUri(String issuer, String account, String secret)
    {
        issuer ??= "Cube";
        account ??= "user";
        var label = Uri.EscapeDataString($"{issuer}:{account}");
        var iss = Uri.EscapeDataString(issuer);
        return $"otpauth://totp/{label}?secret={secret}&issuer={iss}&digits=6&period=30";
    }

    /// <summary>计算当前时间步的验证码</summary>
    public static String ComputeCode(String base32Secret, DateTime? utc = null, Int32 stepSeconds = 30, Int32 digits = 6)
    {
        var key = FromBase32(base32Secret);
        var counter = GetTimeCounter(utc ?? DateTime.UtcNow, stepSeconds);
        return ComputeHotp(key, counter, digits);
    }

    /// <summary>校验验证码，允许前后各 window 个时间步</summary>
    public static Boolean Verify(String base32Secret, String code, Int32 window = 1, Int32 stepSeconds = 30, Int32 digits = 6)
    {
        if (base32Secret.IsNullOrEmpty() || code.IsNullOrEmpty()) return false;
        code = code.Trim();
        if (code.Length != digits) return false;

        var key = FromBase32(base32Secret);
        var counter = GetTimeCounter(DateTime.UtcNow, stepSeconds);
        for (var i = -window; i <= window; i++)
        {
            if (ComputeHotp(key, counter + i, digits) == code) return true;
        }
        return false;
    }

    private static Int64 GetTimeCounter(DateTime utc, Int32 stepSeconds) =>
        (Int64)(utc.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds / stepSeconds;

    private static String ComputeHotp(Byte[] key, Int64 counter, Int32 digits)
    {
        var data = BitConverter.GetBytes(counter);
        if (BitConverter.IsLittleEndian) Array.Reverse(data);

        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(data);
        var offset = hash[^1] & 0x0F;
        var binary =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);
        var otp = binary % (Int32)Math.Pow(10, digits);
        return otp.ToString().PadLeft(digits, '0');
    }

    /// <summary>字节转 Base32</summary>
    public static String ToBase32(Byte[] data)
    {
        if (data == null || data.Length == 0) return String.Empty;

        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        Int32 buffer = data[0], next = 1, bitsLeft = 8;
        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    var pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            var index = (buffer >> (bitsLeft - 5)) & 0x1F;
            bitsLeft -= 5;
            sb.Append(Base32Alphabet[index]);
        }
        return sb.ToString();
    }

    /// <summary>Base32 转字节</summary>
    public static Byte[] FromBase32(String input)
    {
        if (input.IsNullOrEmpty()) return [];

        input = input.Trim().TrimEnd('=').Replace(" ", null).ToUpperInvariant();
        var bytes = new List<Byte>(input.Length * 5 / 8);
        Int32 buffer = 0, bitsLeft = 0;
        foreach (var c in input)
        {
            var val = Base32Alphabet.IndexOf(c);
            if (val < 0) throw new FormatException($"非法 Base32 字符: {c}");
            buffer = (buffer << 5) | val;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                bytes.Add((Byte)((buffer >> (bitsLeft - 8)) & 0xFF));
                bitsLeft -= 8;
            }
        }
        return bytes.ToArray();
    }
}
