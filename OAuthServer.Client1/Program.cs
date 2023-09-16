using Microsoft.AspNetCore.Authentication;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services
    .AddAuthentication("cookie")
    .AddCookie("cookie")
    .AddOAuth("custom", o =>
    {
        o.SignInScheme = "cookie";
        o.ClientId = "c";
        o.ClientSecret = "b";
        o.AuthorizationEndpoint = "https://localhost:3005/oauth/authorize";
        o.TokenEndpoint = "https://localhost:3005/oauth/token";
        o.CallbackPath = "/oauth/custom-cb";
        o.UsePkce = true;
        o.ClaimActions.MapJsonKey("sub", "sub");
        o.ClaimActions.MapJsonKey("custom", "custom");
        o.Events.OnTicketReceived = async trc =>
        {
            trc.ReturnUri = "/";
        };
        o.Events.OnCreatingTicket = async ctx =>
        {
            var payloadBase64 = ctx.AccessToken.Split('.')[1];
            var payloadJson = Base64UrlTextEncoder.Decode(payloadBase64);
            var payloadJsonDocument = JsonDocument.Parse(payloadJson);
            ctx.RunClaimActions(payloadJsonDocument.RootElement);
        };
    });

var app = builder.Build();

app.MapGet("/", (HttpContext ctx) =>
{
    return ctx.User.Claims.Select(x => new { x.Type, x.Value }).ToList();
});

app.MapGet("/login", () => {
    
    return Results.Challenge(new AuthenticationProperties()
    {
        RedirectUri = "https://localhost:3005/"
    },
    authenticationSchemes: new List<string>() { "custom" });
});

//app.UseHttpsRedirection();

app.Run();
