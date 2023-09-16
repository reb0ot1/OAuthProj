using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;

namespace OAuthServer.BlazorSPA.Providers
{
    public class AuthenticationProvider : AuthenticationStateProvider
    {
        private readonly TestDatabase testDatabse;
        public AuthenticationProvider(TestDatabase databaseDict)
        {
            this.testDatabse = databaseDict;
        }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            if (this.testDatabse.ContainsKey("IsAuthenticated") && this.testDatabse["IsAuthenticated"] == "Y")
            { 
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim("test", "val") }, "cookieType")));
            }

            return new AuthenticationState(new ClaimsPrincipal());
        }

        public void NotifyUserAuthentication()
        {
            //var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, email) }, "jwtAuthType"));
            var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(new List<Claim> { new Claim("test", "val") }, "cookieType"))));
            this.NotifyAuthenticationStateChanged(authState);
        }

        public void NotifyUserLogout()
        {
            var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal()));
            this.NotifyAuthenticationStateChanged(authState);
        }
    }
}