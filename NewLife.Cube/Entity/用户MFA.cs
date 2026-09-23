using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.Serialization;
using System.Web.Script.Serialization;
using System.Xml.Serialization;
using NewLife;
using NewLife.Data;
using XCode;
using XCode.Cache;
using XCode.Configuration;
using XCode.DataAccessLayer;

namespace NewLife.Cube.Entity;

/// <summary>用户MFA。二步验证绑定与恢复码</summary>
[Serializable]
[DataObject]
[Description("用户MFA。二步验证绑定与恢复码")]
[BindIndex("IU_UserMfa_UserId", true, "UserId")]
[BindTable("UserMfa", Description = "用户MFA。二步验证绑定与恢复码", ConnName = "Cube", DbType = DatabaseType.None)]
public partial class UserMfa : IEntity<UserMfaModel>
{
    #region 属性
    private Int32 _Id;
    /// <summary>编号</summary>
    [DisplayName("编号")]
    [Description("编号")]
    [DataObjectField(true, true, false, 0)]
    [BindColumn("Id", "编号", "")]
    public Int32 Id { get => _Id; set { if (OnPropertyChanging("Id", value)) { _Id = value; OnPropertyChanged("Id"); } } }

    private Int32 _UserId;
    /// <summary>用户</summary>
    [DisplayName("用户")]
    [Description("用户")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("UserId", "用户", "")]
    public Int32 UserId { get => _UserId; set { if (OnPropertyChanging("UserId", value)) { _UserId = value; OnPropertyChanged("UserId"); } } }

    private Boolean _Enable;
    /// <summary>启用。用户是否启用二步验证</summary>
    [DisplayName("启用")]
    [Description("启用。用户是否启用二步验证")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("Enable", "启用。用户是否启用二步验证", "")]
    public Boolean Enable { get => _Enable; set { if (OnPropertyChanging("Enable", value)) { _Enable = value; OnPropertyChanged("Enable"); } } }

    private String _TotpSecret;
    /// <summary>TOTP密钥。加密存储的Base32密钥</summary>
    [DisplayName("TOTP密钥")]
    [Description("TOTP密钥。加密存储的Base32密钥")]
    [DataObjectField(false, false, true, 200)]
    [BindColumn("TotpSecret", "TOTP密钥。加密存储的Base32密钥", "")]
    public String TotpSecret { get => _TotpSecret; set { if (OnPropertyChanging("TotpSecret", value)) { _TotpSecret = value; OnPropertyChanged("TotpSecret"); } } }

    private Boolean _TotpConfirmed;
    /// <summary>TOTP已确认。完成首码校验后为true</summary>
    [DisplayName("TOTP已确认")]
    [Description("TOTP已确认。完成首码校验后为true")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("TotpConfirmed", "TOTP已确认。完成首码校验后为true", "")]
    public Boolean TotpConfirmed { get => _TotpConfirmed; set { if (OnPropertyChanging("TotpConfirmed", value)) { _TotpConfirmed = value; OnPropertyChanged("TotpConfirmed"); } } }

    private Boolean _SmsEnabled;
    /// <summary>短信通道。允许用短信作第二因子</summary>
    [DisplayName("短信通道")]
    [Description("短信通道。允许用短信作第二因子")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("SmsEnabled", "短信通道。允许用短信作第二因子", "")]
    public Boolean SmsEnabled { get => _SmsEnabled; set { if (OnPropertyChanging("SmsEnabled", value)) { _SmsEnabled = value; OnPropertyChanged("SmsEnabled"); } } }

    private Boolean _MailEnabled;
    /// <summary>邮件通道。允许用邮件作第二因子</summary>
    [DisplayName("邮件通道")]
    [Description("邮件通道。允许用邮件作第二因子")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("MailEnabled", "邮件通道。允许用邮件作第二因子", "")]
    public Boolean MailEnabled { get => _MailEnabled; set { if (OnPropertyChanging("MailEnabled", value)) { _MailEnabled = value; OnPropertyChanged("MailEnabled"); } } }

    private String _BackupCodes;
    /// <summary>恢复码。哈希后的JSON数组</summary>
    [DisplayName("恢复码")]
    [Description("恢复码。哈希后的JSON数组")]
    [DataObjectField(false, false, true, 2000)]
    [BindColumn("BackupCodes", "恢复码。哈希后的JSON数组", "")]
    public String BackupCodes { get => _BackupCodes; set { if (OnPropertyChanging("BackupCodes", value)) { _BackupCodes = value; OnPropertyChanged("BackupCodes"); } } }

    private Int32 _CreateUserID;
    /// <summary>创建用户</summary>
    [Category("扩展")]
    [DisplayName("创建用户")]
    [Description("创建用户")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("CreateUserID", "创建用户", "")]
    public Int32 CreateUserID { get => _CreateUserID; set { if (OnPropertyChanging("CreateUserID", value)) { _CreateUserID = value; OnPropertyChanged("CreateUserID"); } } }

    private String _CreateIP;
    /// <summary>创建地址</summary>
    [Category("扩展")]
    [DisplayName("创建地址")]
    [Description("创建地址")]
    [DataObjectField(false, false, true, 50)]
    [BindColumn("CreateIP", "创建地址", "")]
    public String CreateIP { get => _CreateIP; set { if (OnPropertyChanging("CreateIP", value)) { _CreateIP = value; OnPropertyChanged("CreateIP"); } } }

    private DateTime _CreateTime;
    /// <summary>创建时间</summary>
    [Category("扩展")]
    [DisplayName("创建时间")]
    [Description("创建时间")]
    [DataObjectField(false, false, true, 0)]
    [BindColumn("CreateTime", "创建时间", "")]
    public DateTime CreateTime { get => _CreateTime; set { if (OnPropertyChanging("CreateTime", value)) { _CreateTime = value; OnPropertyChanged("CreateTime"); } } }

    private Int32 _UpdateUserID;
    /// <summary>更新用户</summary>
    [Category("扩展")]
    [DisplayName("更新用户")]
    [Description("更新用户")]
    [DataObjectField(false, false, false, 0)]
    [BindColumn("UpdateUserID", "更新用户", "")]
    public Int32 UpdateUserID { get => _UpdateUserID; set { if (OnPropertyChanging("UpdateUserID", value)) { _UpdateUserID = value; OnPropertyChanged("UpdateUserID"); } } }

    private String _UpdateIP;
    /// <summary>更新地址</summary>
    [Category("扩展")]
    [DisplayName("更新地址")]
    [Description("更新地址")]
    [DataObjectField(false, false, true, 50)]
    [BindColumn("UpdateIP", "更新地址", "")]
    public String UpdateIP { get => _UpdateIP; set { if (OnPropertyChanging("UpdateIP", value)) { _UpdateIP = value; OnPropertyChanged("UpdateIP"); } } }

    private DateTime _UpdateTime;
    /// <summary>更新时间</summary>
    [Category("扩展")]
    [DisplayName("更新时间")]
    [Description("更新时间")]
    [DataObjectField(false, false, true, 0)]
    [BindColumn("UpdateTime", "更新时间", "")]
    public DateTime UpdateTime { get => _UpdateTime; set { if (OnPropertyChanging("UpdateTime", value)) { _UpdateTime = value; OnPropertyChanged("UpdateTime"); } } }

    private String _Remark;
    /// <summary>备注</summary>
    [Category("扩展")]
    [DisplayName("备注")]
    [Description("备注")]
    [DataObjectField(false, false, true, 500)]
    [BindColumn("Remark", "备注", "")]
    public String Remark { get => _Remark; set { if (OnPropertyChanging("Remark", value)) { _Remark = value; OnPropertyChanged("Remark"); } } }
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

    #region 获取/设置 字段值
    /// <summary>获取/设置 字段值</summary>
    /// <param name="name">字段名</param>
    /// <returns></returns>
    public override Object this[String name]
    {
        get => name switch
        {
            "Id" => _Id,
            "UserId" => _UserId,
            "Enable" => _Enable,
            "TotpSecret" => _TotpSecret,
            "TotpConfirmed" => _TotpConfirmed,
            "SmsEnabled" => _SmsEnabled,
            "MailEnabled" => _MailEnabled,
            "BackupCodes" => _BackupCodes,
            "CreateUserID" => _CreateUserID,
            "CreateIP" => _CreateIP,
            "CreateTime" => _CreateTime,
            "UpdateUserID" => _UpdateUserID,
            "UpdateIP" => _UpdateIP,
            "UpdateTime" => _UpdateTime,
            "Remark" => _Remark,
            _ => base[name]
        };
        set
        {
            switch (name)
            {
                case "Id": _Id = value.ToInt(); break;
                case "UserId": _UserId = value.ToInt(); break;
                case "Enable": _Enable = value.ToBoolean(); break;
                case "TotpSecret": _TotpSecret = Convert.ToString(value); break;
                case "TotpConfirmed": _TotpConfirmed = value.ToBoolean(); break;
                case "SmsEnabled": _SmsEnabled = value.ToBoolean(); break;
                case "MailEnabled": _MailEnabled = value.ToBoolean(); break;
                case "BackupCodes": _BackupCodes = Convert.ToString(value); break;
                case "CreateUserID": _CreateUserID = value.ToInt(); break;
                case "CreateIP": _CreateIP = Convert.ToString(value); break;
                case "CreateTime": _CreateTime = value.ToDateTime(); break;
                case "UpdateUserID": _UpdateUserID = value.ToInt(); break;
                case "UpdateIP": _UpdateIP = Convert.ToString(value); break;
                case "UpdateTime": _UpdateTime = value.ToDateTime(); break;
                case "Remark": _Remark = Convert.ToString(value); break;
                default: base[name] = value; break;
            }
        }
    }
    #endregion

    #region 关联映射
    #endregion

    #region 扩展查询
    /// <summary>根据编号查找</summary>
    /// <param name="id">编号</param>
    /// <returns>实体对象</returns>
    public static UserMfa FindById(Int32 id)
    {
        if (id < 0) return null;

        // 实体缓存
        if (Meta.Session.Count < 1000) return Meta.Cache.Find(e => e.Id == id);

        // 单对象缓存
        return Meta.SingleCache[id];

        //return Find(_.Id == id);
    }

    /// <summary>根据用户查找</summary>
    /// <param name="userId">用户</param>
    /// <returns>实体对象</returns>
    public static UserMfa FindByUserId(Int32 userId)
    {
        if (userId < 0) return null;

        // 实体缓存
        if (Meta.Session.Count < 1000) return Meta.Cache.Find(e => e.UserId == userId);

        return Find(_.UserId == userId);
    }
    #endregion

    #region 高级查询
    /// <summary>高级查询</summary>
    /// <param name="userId">用户</param>
    /// <param name="totpConfirmed">TOTP已确认。完成首码校验后为true</param>
    /// <param name="smsEnabled">短信通道。允许用短信作第二因子</param>
    /// <param name="mailEnabled">邮件通道。允许用邮件作第二因子</param>
    /// <param name="enable">启用。用户是否启用二步验证</param>
    /// <param name="start">更新时间开始</param>
    /// <param name="end">更新时间结束</param>
    /// <param name="key">关键字</param>
    /// <param name="page">分页参数信息。可携带统计和数据权限扩展查询等信息</param>
    /// <returns>实体列表</returns>
    public static IList<UserMfa> Search(Int32 userId, Boolean? totpConfirmed, Boolean? smsEnabled, Boolean? mailEnabled, Boolean? enable, DateTime start, DateTime end, String key, PageParameter page)
    {
        var exp = new WhereExpression();

        if (userId >= 0) exp &= _.UserId == userId;
        if (totpConfirmed != null) exp &= _.TotpConfirmed == totpConfirmed;
        if (smsEnabled != null) exp &= _.SmsEnabled == smsEnabled;
        if (mailEnabled != null) exp &= _.MailEnabled == mailEnabled;
        if (enable != null) exp &= _.Enable == enable;
        exp &= _.UpdateTime.Between(start, end);
        if (!key.IsNullOrEmpty()) exp &= SearchWhereByKeys(key);

        return FindAll(exp, page);
    }
    #endregion

    #region 字段名
    /// <summary>取得用户MFA字段信息的快捷方式</summary>
    public partial class _
    {
        /// <summary>编号</summary>
        public static readonly Field Id = FindByName("Id");

        /// <summary>用户</summary>
        public static readonly Field UserId = FindByName("UserId");

        /// <summary>启用。用户是否启用二步验证</summary>
        public static readonly Field Enable = FindByName("Enable");

        /// <summary>TOTP密钥。加密存储的Base32密钥</summary>
        public static readonly Field TotpSecret = FindByName("TotpSecret");

        /// <summary>TOTP已确认。完成首码校验后为true</summary>
        public static readonly Field TotpConfirmed = FindByName("TotpConfirmed");

        /// <summary>短信通道。允许用短信作第二因子</summary>
        public static readonly Field SmsEnabled = FindByName("SmsEnabled");

        /// <summary>邮件通道。允许用邮件作第二因子</summary>
        public static readonly Field MailEnabled = FindByName("MailEnabled");

        /// <summary>恢复码。哈希后的JSON数组</summary>
        public static readonly Field BackupCodes = FindByName("BackupCodes");

        /// <summary>创建用户</summary>
        public static readonly Field CreateUserID = FindByName("CreateUserID");

        /// <summary>创建地址</summary>
        public static readonly Field CreateIP = FindByName("CreateIP");

        /// <summary>创建时间</summary>
        public static readonly Field CreateTime = FindByName("CreateTime");

        /// <summary>更新用户</summary>
        public static readonly Field UpdateUserID = FindByName("UpdateUserID");

        /// <summary>更新地址</summary>
        public static readonly Field UpdateIP = FindByName("UpdateIP");

        /// <summary>更新时间</summary>
        public static readonly Field UpdateTime = FindByName("UpdateTime");

        /// <summary>备注</summary>
        public static readonly Field Remark = FindByName("Remark");

        static Field FindByName(String name) => Meta.Table.FindByName(name);
    }

    /// <summary>取得用户MFA字段名称的快捷方式</summary>
    public partial class __
    {
        /// <summary>编号</summary>
        public const String Id = "Id";

        /// <summary>用户</summary>
        public const String UserId = "UserId";

        /// <summary>启用。用户是否启用二步验证</summary>
        public const String Enable = "Enable";

        /// <summary>TOTP密钥。加密存储的Base32密钥</summary>
        public const String TotpSecret = "TotpSecret";

        /// <summary>TOTP已确认。完成首码校验后为true</summary>
        public const String TotpConfirmed = "TotpConfirmed";

        /// <summary>短信通道。允许用短信作第二因子</summary>
        public const String SmsEnabled = "SmsEnabled";

        /// <summary>邮件通道。允许用邮件作第二因子</summary>
        public const String MailEnabled = "MailEnabled";

        /// <summary>恢复码。哈希后的JSON数组</summary>
        public const String BackupCodes = "BackupCodes";

        /// <summary>创建用户</summary>
        public const String CreateUserID = "CreateUserID";

        /// <summary>创建地址</summary>
        public const String CreateIP = "CreateIP";

        /// <summary>创建时间</summary>
        public const String CreateTime = "CreateTime";

        /// <summary>更新用户</summary>
        public const String UpdateUserID = "UpdateUserID";

        /// <summary>更新地址</summary>
        public const String UpdateIP = "UpdateIP";

        /// <summary>更新时间</summary>
        public const String UpdateTime = "UpdateTime";

        /// <summary>备注</summary>
        public const String Remark = "Remark";
    }
    #endregion
}
