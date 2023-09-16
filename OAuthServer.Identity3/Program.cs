using Microsoft.AspNetCore.Authentication;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

//builder.Services.AddAuthentication("cookie")
//    .AddCookie("cookie", option => {
//        option.Cookie.SameSite = SameSiteMode.Lax;
//    });

//builder.Services.AddCors(options =>
//{
//    //options.AddPolicy("blazor", setup => setup.WithHeaders("blazorH"));
//    options.AddPolicy("blazor", setup => setup
//    .WithOrigins("https://localhost:7157")
//    .AllowAnyHeader()
//    .AllowAnyMethod()
//    .AllowCredentials()
//    );
//});

//builder.Services.AddAuthorization();

// Add services to the container.

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseHttpsRedirection();
app.UseCors("blazor");
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/test", () => "Hi there!");

app.MapGet("/login", async (HttpContext ctx) =>
{
    await ctx.SignInAsync("cookie", new ClaimsPrincipal(new ClaimsIdentity(new Claim[] { new Claim("test1", "value1")}, "cookie")));

    return Results.Ok();
});

app.MapPost("/getData", () =>
{
    return Results.Json(new
    {
        Prop = "1",
        Prop2 = "Test"
    });
}).RequireAuthorization();

app.Run();