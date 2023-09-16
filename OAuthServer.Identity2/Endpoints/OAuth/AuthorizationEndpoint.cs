using Microsoft.AspNetCore.DataProtection;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;

namespace OAuthServer.Identity2.Endpoints.OAuth
{
    public static class AuthorizationEndpoint
    {
        public static IResult Handle(HttpRequest request, IDataProtectionProvider dataProtectionProvider)
        {

            request.Query.TryGetValue("response_type", out var responseType);
            request.Query.TryGetValue("client_id", out var clientId);
            request.Query.TryGetValue("code_challenge", out var codeChallange);
            request.Query.TryGetValue("code_challenge_method", out var codeChallangeMethod);
            request.Query.TryGetValue("redirect_uri", out var redirectUri);
            request.Query.TryGetValue("scope", out var scope);
            request.Query.TryGetValue("state", out var state);

            var protecor = dataProtectionProvider.CreateProtector("oauth");

            var auth = new OAuthCodeModel
            {
                ClientId = clientId,
                CodeChallange = codeChallange,
                CodeChallangeMethod = codeChallangeMethod,
                RedirectUri = redirectUri,
                Expiry = DateTime.Now.AddMinutes(5)
            };

            var codeString = protecor.Protect(JsonSerializer.Serialize(auth));

            return Results.Redirect($"{redirectUri}?code={codeString}&state={state}&iss={HttpUtility.UrlEncode("https://localhost:3005")}");
        }
    }
}
