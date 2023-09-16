using System.ComponentModel;

namespace OAuthServer.Identity.Models
{
    internal enum AuthorizationGrantTypesEnum : byte
    {
        [Description("code")]
        Code,

        [Description("Implicit")]
        Implicit,

        [Description("ClientCredentials")]
        ClientCredentials,

        [Description("ResourceOwnerPassword")]
        ResourceOwnerPassword
    }
}
