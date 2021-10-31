using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace JWT.Extensions 
{
    public static class JWTRSAAuth 
    {
        public static AuthenticationBuilder AddJWTRSAAuth(this IServiceCollection collection, IConfiguration Configuration)
        {
            return collection.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options => {
                RsaSecurityKey key;
                //using(RSA rsa = RSA.Create())
                //{
                RSA rsa = RSA.Create();
                  rsa.ImportRSAPublicKey(Convert.FromBase64String(Configuration["JWT:Keys:Public"]), out int _);
                  key = new RsaSecurityKey(rsa){CryptoProviderFactory = new CryptoProviderFactory(){ CacheSignatureProviders = false }};
                //}

                options.TokenValidationParameters = new TokenValidationParameters()
                  {
                      IssuerSigningKey = key,
                      ValidAudience = "jwt-test",
                      ValidIssuer = "jwt-test",
                      RequireSignedTokens = true,
                      RequireExpirationTime = true,
                      ValidateLifetime = true,
                  };
            });
         
        }
    }
}