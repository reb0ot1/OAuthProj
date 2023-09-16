using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using Microsoft.AspNetCore.Components.WebAssembly.Http;
using OAuthServer.BlazorSPA;
using OAuthServer.BlazorSPA.Providers;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");
builder.Services.AddAuthorizationCore();
builder.Services.AddScoped<AuthenticationStateProvider, AuthenticationProvider>();
builder.Services.AddScoped<CustomAuthorization>();
builder.Services.AddSingleton<TestDatabase>();
builder.Services.AddScoped(sp => new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddHttpClient("apiclient", o => {
    o.BaseAddress = new Uri("https://localhost:7055");
})
    .AddHttpMessageHandler<CustomAuthorization>();

await builder.Build().RunAsync();

public class CustomAuthorization : DelegatingHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        request.SetBrowserRequestCredentials(BrowserRequestCredentials.Include);
        //request.Headers.Add("blazorH", "Y");

        return base.SendAsync(request, cancellationToken);
    }
}

public class TestDatabase : Dictionary<string, string>
{
}