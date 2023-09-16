using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, o =>
    {
        o.ClientId = "test1";
        o.ClientSecret = "1234test";
        o.Authority = "https://localhost:5056";
        o.CallbackPath = "/signin-oidc";
        o.ResponseType = "code";
        o.SaveTokens = true;
        o.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
        {
            ValidateIssuerSigningKey = false,
            SignatureValidator = (string token, TokenValidationParameters validationParams) => 
            {
                var jwt = new JwtSecurityToken(token);
                return jwt;
            }
        };
        o.Events.OnTicketReceived = (x) =>
        {
            return Task.CompletedTask;
        };
        o.Events.OnTokenResponseReceived = (x) =>
        {
            return Task.CompletedTask;
        };
        o.Events.OnTokenValidated = (x) => {

            //Console.WriteLine(x.Request.HttpContext);
            return Task.CompletedTask; 
        };
    });

builder.Services.AddControllersWithViews();

var app = builder.Build();
app.UseStaticFiles();
app.MapGet("/", 
    (HttpContext ctx) => {
        return "Hello World!"; 
    })
    .RequireAuthorization();
app.UseHttpsRedirection()
                .UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());

app.Run();
