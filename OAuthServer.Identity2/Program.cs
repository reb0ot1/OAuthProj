using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OAuthServer.Identity2;
using OAuthServer.Identity2.Endpoints;
using OAuthServer.Identity2.Endpoints.OAuth;
using System.Security.Claims;
using System.Text.Json;
using System.Text;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie", options =>
    {
        options.LoginPath = "/login";
    });
builder.Services.AddAuthorization();
builder.Services.AddSingleton<DevKeys>();

var app = builder.Build();

app.MapGet("/login", GetLogin.Handler);
app.MapPost("/login", async (HttpContext httpContext, string returnUrl) =>
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
        });
app.MapGet("/oauth/authorize", AuthorizationEndpoint.Handle).RequireAuthorization();
app.MapPost("/oauth/token", async (HttpRequest httpRequest, DevKeys devKeys, IDataProtectionProvider dataProtectionProvider) =>
        {
            httpRequest.EnableBuffering();
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

            using var sha256 = SHA256.Create();
            var codeChallange = Base64UrlEncoder.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier)));


            if (!(authCode.CodeChallange == codeChallange))
            {
                return Results.BadRequest();
            }

            var handler = new JsonWebTokenHandler();

    return Results.Ok(new
    {
        access_token = handler.CreateToken(new SecurityTokenDescriptor()
        {
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = Guid.NewGuid().ToString(),
                ["custom"] = "foo"
            },
            Expires = DateTime.UtcNow.AddMinutes(15),
            TokenType = "Bearer",
            SigningCredentials = new SigningCredentials(devKeys.RsaSecurityKey, SecurityAlgorithms.RsaSha256)
        }),
        token_type = "Bearer"
    });
});

app.Run();