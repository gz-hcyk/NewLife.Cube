using System;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using NewLife;
using XCode;
using XCode.Membership;

namespace NewLife.Cube.Entity;

/// <summary>用户MFA。二步验证绑定与恢复码</summary>
public partial class UserMfa : Entity<UserMfa>
{
    #region 对象操作
    static UserMfa()
    {
        Meta.Modules.Add(new UserModule { AllowEmpty = false });
        Meta.Modules.Add<TimeModule>();
        Meta.Modules.Add(new IPModule { AllowEmpty = false });
    }

    /// <summary>验证并修补数据</summary>
    public override Boolean Valid(DataMethod method)
    {
        if (!HasDirty) return true;
        if (method != DataMethod.Delete && UserId <= 0)
            throw new ArgumentOutOfRangeException(nameof(UserId));
        return base.Valid(method);
    }
    #endregion

    #region 扩展属性
    /// <summary>用户</summary>
    [XmlIgnore, ScriptIgnore, IgnoreDataMember]
    public User User => Extends.Get(nameof(User), k => User.FindByID(UserId));

    /// <summary>用户名</summary>
    [Map(nameof(UserId))]
    public String UserName => User + "";

    /// <summary>是否已绑定可用第二因子（不含仅恢复码）</summary>
    public Boolean HasBoundFactor =>
        (TotpConfirmed && !TotpSecret.IsNullOrEmpty()) || SmsEnabled || MailEnabled;

    /// <summary>是否处于可用 MFA 状态</summary>
    public Boolean IsActive => Enable && (HasBoundFactor || !BackupCodes.IsNullOrEmpty());
    #endregion

    #region 业务操作
    /// <summary>获取或创建用户 MFA 档案</summary>
    public static UserMfa GetOrCreate(Int32 userId)
    {
        if (userId <= 0) throw new ArgumentOutOfRangeException(nameof(userId));

        var entity = FindByUserId(userId);
        if (entity != null) return entity;

        entity = new UserMfa { UserId = userId, Enable = false };
        entity.Insert();
        return entity;
    }

    /// <summary>转为模型</summary>
    public UserMfaModel ToModel()
    {
        return new UserMfaModel
        {
            Id = Id,
            UserId = UserId,
            Enable = Enable,
            TotpSecret = TotpSecret,
            TotpConfirmed = TotpConfirmed,
            SmsEnabled = SmsEnabled,
            MailEnabled = MailEnabled,
            BackupCodes = BackupCodes,
            CreateUserID = CreateUserID,
            CreateIP = CreateIP,
            CreateTime = CreateTime,
            UpdateUserID = UpdateUserID,
            UpdateIP = UpdateIP,
            UpdateTime = UpdateTime,
            Remark = Remark,
        };
    }
    #endregion
}
