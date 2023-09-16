using OAuthServer.Identity.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton<ICodeStoreService, CodeStoreService>();
builder.Services.AddSingleton<IAuthorizationResultService, AuthorizationResultService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddControllersWithViews();

var app = builder.Build();

//app.MapGet("/", () => "Hello World!");
app.UseStaticFiles();
app.UseHttpsRedirection()
                .UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseEndpoints(endpoints => endpoints.MapDefaultControllerRoute());

app.Run();
