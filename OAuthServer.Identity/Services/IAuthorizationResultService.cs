using OAuthServer.Identity.Requests;
using OAuthServer.Identity.Response;

namespace OAuthServer.Identity.Services
{
    public interface IAuthorizationResultService
    {
        AuthorizeResponse AuthorizeRequest(IHttpContextAccessor httpContextAccessor, AuthorizationRequest authorizationRequest);

        TokenResponse GenerateToken(IHttpContextAccessor httpContextAccessor);
    }
}
