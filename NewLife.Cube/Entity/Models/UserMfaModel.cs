using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using System.Xml.Serialization;

namespace NewLife.Cube.Entity;

/// <summary>用户MFA。二步验证绑定与恢复码</summary>
public partial class UserMfaModel
{
    #region 属性
    /// <summary>编号</summary>
    public Int32 Id { get; set; }

    /// <summary>用户</summary>
    public Int32 UserId { get; set; }

    /// <summary>启用。用户是否启用二步验证</summary>
    public Boolean Enable { get; set; }

    /// <summary>TOTP密钥。加密存储的Base32密钥</summary>
    public String TotpSecret { get; set; }

    /// <summary>TOTP已确认。完成首码校验后为true</summary>
    public Boolean TotpConfirmed { get; set; }

    /// <summary>短信通道。允许用短信作第二因子</summary>
    public Boolean SmsEnabled { get; set; }

    /// <summary>邮件通道。允许用邮件作第二因子</summary>
    public Boolean MailEnabled { get; set; }

    /// <summary>恢复码。哈希后的JSON数组</summary>
    public String BackupCodes { get; set; }

    /// <summary>创建用户</summary>
    public Int32 CreateUserID { get; set; }

    /// <summary>创建地址</summary>
    public String CreateIP { get; set; }

    /// <summary>创建时间</summary>
    public DateTime CreateTime { get; set; }

    /// <summary>更新用户</summary>
    public Int32 UpdateUserID { get; set; }

    /// <summary>更新地址</summary>
    public String UpdateIP { get; set; }

    /// <summary>更新时间</summary>
    public DateTime UpdateTime { get; set; }

    /// <summary>备注</summary>
    public String Remark { get; set; }
    #endregion

    #region 拷贝
    /// <summary>拷贝模型对象</summary>
    /// <param name="model">模型</param>
    public void Copy(UserMfaModel model)
    {
        Id = model.Id;
        UserId = model.UserId;
        Enable = model.Enable;
        TotpSecret = model.TotpSecret;
        TotpConfirmed = model.TotpConfirmed;
        SmsEnabled = model.SmsEnabled;
        MailEnabled = model.MailEnabled;
        BackupCodes = model.BackupCodes;
        CreateUserID = model.CreateUserID;
        CreateIP = model.CreateIP;
        CreateTime = model.CreateTime;
        UpdateUserID = model.UpdateUserID;
        UpdateIP = model.UpdateIP;
        UpdateTime = model.UpdateTime;
        Remark = model.Remark;
    }
    #endregion
}
