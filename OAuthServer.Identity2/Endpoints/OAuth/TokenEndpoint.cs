using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OAuthServer.Identity2.Endpoints.OAuth
{
    public static class TokenEndpoint
    {
        public static async Task<IResult> Handle(HttpRequest httpRequest, DevKeys devKeys, IDataProtectionProvider dataProtectionProvider)
        {
            var bodyBytes = await httpRequest.BodyReader.ReadAsync();
            var bodyContent = Encoding.UTF8.GetString(bodyBytes.Buffer);

            string grantType = "", code = "", redirectUri = "", codeVerifier = "";
            foreach (var item in bodyContent.Split("&"))
            {
                var subParts = item.Split("=");
                var key = subParts[0];
                var value = subParts[1];

                if (key == "grant_type") grantType = value;
                else if (key == "code") code = value;
                else if (key == "redirect_uri") redirectUri = value;
                else if (key == "code_verifier") codeVerifier = value;
            }

            var protector = dataProtectionProvider.CreateProtector("oauth");
            var unprotect = protector.Unprotect(code);

            var authCode = JsonSerializer.Deserialize<OAuthCodeModel>(unprotect);

            if (!ValidateCodeVerifier(authCode, codeVerifier))
            {
                return Results.BadRequest();
            }

            httpRequest.Query.TryGetValue("code", out var scope);
            
            var handler = new JsonWebTokenHandler();

            return Results.Ok(new { 
                access_token = handler.CreateToken(new SecurityTokenDescriptor() { 
                    Claims = new Dictionary<string, object> {
                        [JwtRegisteredClaimNames.Sub] = Guid.NewGuid().ToString(),
                        ["custom"] = "foo"
                    },
                    Expires = DateTime.UtcNow.AddMinutes(15),
                    TokenType = "Bearer",
                    SigningCredentials = new SigningCredentials(devKeys.RsaSecurityKey, SecurityAlgorithms.RsaSha256)
                }),
                token_type = "Bearer"
            });
        }

        private static bool ValidateCodeVerifier(OAuthCodeModel code, string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var codeChallange = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));

            return code.CodeChallange == codeChallange;
        }
    }
}
