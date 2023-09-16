namespace OAuthServer.Identity2
{
    public class OAuthCodeModel
    {
        public string ClientId { get; set; }

        public string CodeChallange { get; set; }

        public string CodeChallangeMethod { get; set; }

        public string RedirectUri { get; set; }

        public DateTime Expiry { get; set; }
    }
}
