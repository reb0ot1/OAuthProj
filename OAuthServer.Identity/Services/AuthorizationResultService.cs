using Microsoft.IdentityModel.Tokens;
using OAuthServer.Identity.Common;
using OAuthServer.Identity.Models;
using OAuthServer.Identity.Requests;
using OAuthServer.Identity.Response;
using System.Diagnostics.SymbolStore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace OAuthServer.Identity.Services
{
    public class AuthorizationResultService : IAuthorizationResultService
    {
        private static string keyAlg = "66007d41-6924-49f2-ac0c-e63c4b1a1730";
        private readonly ClientStore _clientStore = new ClientStore();
        private readonly ICodeStoreService _codeStoreService;

        public AuthorizationResultService(ICodeStoreService codeStoreService)
        {
            this._codeStoreService = codeStoreService;
        }

        public AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest)
        {
            AuthorizeResponse response = new AuthorizeResponse();
            if (httpContextAccessor == null)
            {
                return new AuthorizeResponse { Error = ErrorTypeEnum.ServerError.GetEnumDescription() };
            }

            var client = this.VerifyClientById(authorizationRequest.client_id);
            if (!client.IsSuccess)
            {
                return new AuthorizeResponse { Error = client.ErrorDescription };
            }

            if (string.IsNullOrEmpty(authorizationRequest.response_type) || authorizationRequest.response_type != "code")
            {
                return new AuthorizeResponse { 
                    Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription(), 
                    ErrorDescription = "response_type is required or is not valid" 
                };
            }

            if (!authorizationRequest.redirect_uri.IsRedirectUriStartWithHttps() && !httpContextAccessor.HttpContext.Request.IsHttps)
            {
                return new AuthorizeResponse
                {
                    Error = ErrorTypeEnum.InvalidRequest.GetEnumDescription(),
                    ErrorDescription = "redirect_url is not secure, MUST be TLS"
                };
            }

            var scopes = authorizationRequest.scope.Split(' ');

            var clientScopes2 = client.Client.AllowedScopes.Where(w => scopes.Contains(w))
                .Select(e => e)
                .ToList();

            if (!clientScopes2.Any())
            {
                return new AuthorizeResponse
                {
                    Error = ErrorTypeEnum.InValidScope.GetEnumDescription(),
                    ErrorDescription = "scopes are invalids"
                };
            }

            string nonce = httpContextAccessor.HttpContext.Request.Query["nonce"].ToString();
            string code = this._codeStoreService.GenerateAuthorizationCode(authorizationRequest.client_id, clientScopes2);
            if (code == null)
            {
                return new AuthorizeResponse
                {
                    Error = ErrorTypeEnum.TemporarilyUnAvailable.GetEnumDescription()
                };
            }

            return new AuthorizeResponse
            {
                RedirectUri = client.Client.RedirectUri + "?response_type=code" + "&state=" + authorizationRequest.state,
                Code = code,
                State = authorizationRequest.state,
                RequestedScopes = clientScopes2,
                Nonce = nonce
            };
        }

        public TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor)
        {
            TokenRequest request = new TokenRequest();

            request.CodeVerifier = httpContextAccessor.HttpContext.Request.Form["code_verifier"];
            request.ClientId = httpContextAccessor.HttpContext.Request.Form["client_id"];
            request.ClientSecret = httpContextAccessor.HttpContext.Request.Form["client_secret"];
            request.Code = httpContextAccessor.HttpContext.Request.Form["code"];
            request.GrantType = httpContextAccessor.HttpContext.Request.Form["grant_type"];
            request.RedirectUri = httpContextAccessor.HttpContext.Request.Form["redirect_uri"];

            var checkClientResult = this.VerifyClientById(request.ClientId, true, request.ClientSecret);
            if (!checkClientResult.IsSuccess)
            {
                return new TokenResponse { Error = checkClientResult.Error, ErrorDescription = checkClientResult.ErrorDescription };
            }

            // check code from the Concurrent Dictionary
            var clientCodeChecker = _codeStoreService.GetClientDataByCode(request.Code);
            if (clientCodeChecker == null)
                return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };


            // check if the current client who is one made this authentication request

            if (request.ClientId != clientCodeChecker.ClientId)
                return new TokenResponse { Error = ErrorTypeEnum.InvalidGrant.GetEnumDescription() };

            // TODO: 
            // also I have to check the rediret uri 


            // Now here I will Issue the Id_token

            JwtSecurityToken id_token = null;
            if (clientCodeChecker.IsOpenId)
            {
                int iat = (int)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;

                string[] amrs = new string[] { "pwd" };

                var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
                var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
                var claims = new List<Claim>()
                {
                    new Claim("sub", "856933325856"),
                    new Claim("given_name", "Mohammed Ahmed Hussien"),
                    new Claim("iat", iat.ToString(), ClaimValueTypes.Integer), // time stamp
                    new Claim("nonce", clientCodeChecker.Nonce)
                };

                foreach (var amr in amrs)
                    claims.Add(new Claim("amr", amr));// authentication method reference 

                id_token = new JwtSecurityToken("https://localhost:5056", request.ClientId, claims, signingCredentials: credentials,
                    expires: DateTime.UtcNow.AddMinutes(
                       int.Parse("5")));
            }

            // Here I have to generate access token 
            var key_at = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyAlg));
            var credentials_at = new SigningCredentials(key_at, SecurityAlgorithms.HmacSha256);

            var claims_at = new List<Claim>();

            var access_token = new JwtSecurityToken("https://localhost:5056", request.ClientId, claims_at, signingCredentials: credentials_at,
                expires: DateTime.UtcNow.AddMinutes(
                   int.Parse("5")));

            // here remoce the code from the Concurrent Dictionary
            _codeStoreService.RemoveClientDataByCode(request.Code);

            return new TokenResponse
            {
                access_token = new JwtSecurityTokenHandler().WriteToken(access_token),
                id_token = id_token != null ? new JwtSecurityTokenHandler().WriteToken(id_token) : null,
                code = request.Code
            };
        }

        private CheckClientResult VerifyClientById(string clientId, bool checkWithSecret = false, string clientSecret = null)
        {
            var accessDeniedMessage = ErrorTypeEnum.AccessDenied.GetEnumDescription();
            if (string.IsNullOrEmpty(clientId))
            {
                return new CheckClientResult { IsSuccess = false, ErrorDescription = accessDeniedMessage };
            }

            var client = _clientStore.Clients.FirstOrDefault(x => x.ClientId.Equals(clientId, StringComparison.OrdinalIgnoreCase));
            if (client == null)
            {
                return new CheckClientResult { IsSuccess = false, ErrorDescription = accessDeniedMessage };
            }

            if (checkWithSecret && !string.IsNullOrEmpty(clientSecret))
            {
                bool hasSamesecretId = client.ClientSecret.Equals(clientSecret, StringComparison.InvariantCulture);
                if (!hasSamesecretId)
                {
                    return new CheckClientResult { IsSuccess = false, ErrorDescription = ErrorTypeEnum.InvalidClient.GetEnumDescription() };
                }
            }

            // check if client is disabled

            if (!client.IsActive)
            {
                return new CheckClientResult { IsSuccess = false, ErrorDescription = ErrorTypeEnum.UnAuthoriazedClient.GetEnumDescription() };
            }

            return new CheckClientResult { IsSuccess = true, Client = client};
        }
    }
}
