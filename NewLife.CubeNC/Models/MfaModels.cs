using NewLife.Cube.Entity;

namespace NewLife.Cube.Models;

/// <summary>MFA 挑战信息（登录第二步）</summary>
public class MfaChallengeModel
{
    /// <summary>短期挑战令牌</summary>
    public String MfaToken { get; set; }

    /// <summary>有效秒数</summary>
    public Int32 ExpireIn { get; set; }

    /// <summary>可用通道：totp / sms / mail / backup</summary>
    public String[] Methods { get; set; }

    /// <summary>用户显示名（可选）</summary>
    public String DisplayName { get; set; }
}

/// <summary>校验 MFA 请求</summary>
public class VerifyMfaModel
{
    /// <summary>挑战令牌</summary>
    public String MfaToken { get; set; }

    /// <summary>通道：totp / sms / mail / backup</summary>
    public String Method { get; set; }

    /// <summary>验证码或恢复码</summary>
    public String Code { get; set; }
}

/// <summary>发送 MFA 通道验证码</summary>
public class SendMfaCodeModel
{
    /// <summary>挑战令牌</summary>
    public String MfaToken { get; set; }

    /// <summary>通道：sms / mail</summary>
    public String Method { get; set; }
}

/// <summary>用户 MFA 状态（安全设置页）</summary>
public class MfaStatusModel
{
    /// <summary>全局是否启用 MFA</summary>
    public Boolean GlobalEnabled { get; set; }

    /// <summary>是否强制绑定</summary>
    public Boolean Required { get; set; }

    /// <summary>用户是否启用</summary>
    public Boolean Enable { get; set; }

    /// <summary>TOTP 是否已绑定确认</summary>
    public Boolean TotpConfirmed { get; set; }

    /// <summary>短信通道</summary>
    public Boolean SmsEnabled { get; set; }

    /// <summary>邮件通道</summary>
    public Boolean MailEnabled { get; set; }

    /// <summary>脱敏手机</summary>
    public String MobileMasked { get; set; }

    /// <summary>脱敏邮箱</summary>
    public String MailMasked { get; set; }

    /// <summary>手机是否已验证</summary>
    public Boolean MobileVerified { get; set; }

    /// <summary>邮箱是否已验证</summary>
    public Boolean MailVerified { get; set; }

    /// <summary>剩余恢复码数量</summary>
    public Int32 BackupCodeCount { get; set; }
}

/// <summary>TOTP 绑定开始结果</summary>
public class TotpSetupModel
{
    /// <summary>明文密钥（仅此流程展示）</summary>
    public String Secret { get; set; }

    /// <summary>otpauth URI</summary>
    public String OtpAuthUri { get; set; }

    /// <summary>签发方</summary>
    public String Issuer { get; set; }
}

/// <summary>通道启停请求</summary>
public class MfaChannelModel
{
    /// <summary>通道：sms / mail</summary>
    public String Channel { get; set; }

    /// <summary>是否启用</summary>
    public Boolean Enable { get; set; }
}

/// <summary>关闭 MFA / 敏感操作确认</summary>
public class MfaConfirmModel
{
    /// <summary>通道（可选，默认尝试 totp）</summary>
    public String Method { get; set; }

    /// <summary>验证码或密码</summary>
    public String Code { get; set; }
}
