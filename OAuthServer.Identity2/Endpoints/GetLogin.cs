using Microsoft.AspNetCore.Html;
using System.Web;

namespace OAuthServer.Identity2.Endpoints
{
    public static class GetLogin
    {

        public static async Task Handler(string returnUrl, HttpResponse httpResponse)
        {
            httpResponse.Headers.ContentType = new string[] { "text/html" };
            var newString = new HtmlString($"<html><head>Login page</head><body><form action=\"/login?returnUrl={HttpUtility.UrlEncode(returnUrl)}\" method=\"post\"><input value=\"Submit\" type=\"submit\"></form></body></html>");
            await httpResponse.WriteAsync(
               newString.Value
                );
        }
    }
}
