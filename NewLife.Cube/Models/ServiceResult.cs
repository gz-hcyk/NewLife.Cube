namespace NewLife.Cube.Models;

/// <summary>服务操作结果</summary>
public class ServiceResult
{
    /// <summary>是否成功</summary>
    public Boolean IsSuccess { get; set; }

    /// <summary>业务码。0 成功；1002 需 MFA；1003 须绑定 MFA；其它见 CubeCode</summary>
    public Int32 Code { get; set; }

    /// <summary>消息</summary>
    public String Message { get; set; } = String.Empty;
}

/// <summary>服务操作结果</summary>
public class ServiceResult<T> : ServiceResult
{
    /// <summary>数据</summary>
    public T Data { get; set; } = default;

    /// <summary>附加数据（如 MFA 挑战）</summary>
    public Object Extra { get; set; }
}
