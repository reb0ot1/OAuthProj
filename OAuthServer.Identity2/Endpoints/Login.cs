using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

namespace OAuthServer.Identity2.Endpoints
{
    public static class Login
    {
        public static async Task<IResult> Handler(HttpContext httpContext, string returnUrl)
        {
            await httpContext.SignInAsync(
                "cookie",
                new ClaimsPrincipal(
                        new ClaimsIdentity(
                                new Claim[] {
                                    new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString())
                                },
                                "cookie"
                            )
                    )
                );

            return Results.Redirect(returnUrl);
        }
    }
}
