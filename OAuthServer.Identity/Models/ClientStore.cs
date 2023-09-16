namespace OAuthServer.Identity.Models
{
    public class ClientStore
    {
        public IEnumerable<Client> Clients = new[]
        {
            new Client
            {
                ClientName = "platformnet .Net 6",
                ClientId = "test1",
                ClientSecret = "1234test",
                AllowedScopes = new[]{ "openid", "profile"},
                GrantType = GrantTypes.Code,
                IsActive = true,
                ClientUri = "https://localhost:7135",
                RedirectUri = "https://localhost:7135/signin-oidc"
            }
        };
    }
}
