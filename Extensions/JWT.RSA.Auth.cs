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
        public static AuthenticationBuilder AddJWTRSAAuth(this IServiceCollection services, IConfiguration Configuration)
        {
            return services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options => {

                RSA rsa = RSA.Create();

                rsa.ImportRSAPublicKey(Convert.FromBase64String(Configuration["JWT:Keys:Public"]), out int _);

                options.TokenValidationParameters = new TokenValidationParameters()
                  {
                      ValidateIssuerSigningKey = true,
                      ValidateAudience = true,
                      ValidateIssuer = true,
                      ValidateLifetime = true,
                      IssuerSigningKey = new RsaSecurityKey(rsa),
                      ValidAudience = "jwt-test",
                      ValidIssuer = "jwt-test"
                  };
            });       
        }
    }
}