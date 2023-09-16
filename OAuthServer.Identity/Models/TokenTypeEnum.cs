using System.ComponentModel;

namespace OAuthServer.Identity.Models
{
    public enum TokenTypeEnum : byte
    {
        [Description("Bearer")]
        Bearer
    }
}
