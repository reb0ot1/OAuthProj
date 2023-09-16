using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using OAuthServer.Identity.Models;
using System.Collections.Concurrent;
using System.Security.Claims;

namespace OAuthServer.Identity.Services
{
    public class CodeStoreService : ICodeStoreService
    {
        private readonly ConcurrentDictionary<string, AuthorizationCode> _codeIssued 
            = new ConcurrentDictionary<string, AuthorizationCode>();

        private readonly ClientStore _clientStore = new ClientStore();

        public CodeStoreService()
        {

        }

        public string GenerateAuthorizationCode(string clientId, IList<string> requestedScope)
        {
            var client = this._clientStore.Clients.FirstOrDefault(e => e.ClientId == clientId);
            if (client == null)
            {
                return null;
            }
            var code = Guid.NewGuid().ToString();
            var authoCode = new AuthorizationCode
            {
                ClientId = clientId,
                RedirectUri = client.RedirectUri,
                RequestedScopes = requestedScope
            };

            this._codeIssued.TryAdd(code, authoCode);

            return code;
        }

        public AuthorizationCode GetClientDataByCode(string code)
        {
            var valueResult = this._codeIssued.TryGetValue(code, out AuthorizationCode result);
            if (valueResult)
            {
                return result;
            }

            return null;
        }

        public AuthorizationCode RemoveClientDataByCode(string code)
        {
            var removeResult = this._codeIssued.TryRemove(code, out AuthorizationCode result);

            return null;
        }

        public AuthorizationCode UpdateClientDataByCode(string code, IList<string> requestdScopes, string userName, string password = null, string nonce = null)
        {
            AuthorizationCode oldClient = this.GetClientDataByCode(code);
            if (oldClient == null)
            {
                return null;
            }

            var client = _clientStore.Clients.FirstOrDefault(x => x.ClientId == oldClient.ClientId);
            if (client == null)
            {
                return null;
            }

            var clientScope = (from m in client.AllowedScopes
                               where requestdScopes.Contains(m)
                               select m).ToList();

            if (!clientScope.Any())
                return null;

            AuthorizationCode newValue = new AuthorizationCode
            {
                ClientId = oldClient.ClientId,
                CreationTime = oldClient.CreationTime,
                IsOpenId = requestdScopes.Contains("openId") || requestdScopes.Contains("profile"),
                RedirectUri = oldClient.RedirectUri,
                RequestedScopes = requestdScopes,
                Nonce = nonce
            };


            // ------------------ I suppose the user name and password is correct  -----------------
            var claims = new List<Claim>();

            if (newValue.IsOpenId)
            {
                // TODO
                // Add more claims to the claims

            }

            var claimIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            newValue.Subject = new ClaimsPrincipal(claimIdentity);
            // ------------------ -----------------------------------------------  -----------------

            var result = _codeIssued.TryUpdate(code, newValue, oldClient);
            if (!result)
            {
                return null;
            }


            return newValue;
        }
    }
}
