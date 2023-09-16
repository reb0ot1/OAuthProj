using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace OAuthServer.Identity2
{
    public class DevKeys
    {
        public DevKeys(IWebHostEnvironment env)
        {
            this.RsaKeys = RSA.Create();
            var path = Path.Combine(env.ContentRootPath, "crypto_key");
            if (File.Exists(path))
            {
                var rsaKey = RSA.Create();
                rsaKey.ImportRSAPrivateKey(File.ReadAllBytes(path), out _);
            }
            else
            {
                var privateKey = this.RsaKeys.ExportRSAPrivateKey();
                File.WriteAllBytes(path, privateKey);
            }


        }

        public RSA RsaKeys { get; }

        public RsaSecurityKey RsaSecurityKey => new RsaSecurityKey(RsaKeys);
    }
}
