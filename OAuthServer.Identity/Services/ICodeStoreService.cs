using OAuthServer.Identity.Models;

namespace OAuthServer.Identity.Services
{
    public interface ICodeStoreService
    {
        string GenerateAuthorizationCode(string clientId, IList<string> requestedScope);
        AuthorizationCode GetClientDataByCode(string code);
        AuthorizationCode RemoveClientDataByCode(string code);

        AuthorizationCode UpdateClientDataByCode(string code, IList<string> requestdScopes,
            string userName, string password = null, string nonce = null);
    }
}
