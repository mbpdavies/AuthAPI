using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

namespace JWT.Controllers 
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthorisationController : ControllerBase 
    {
        private readonly IConfiguration _config;
        public AuthorisationController(IConfiguration config)
        {
            _config = config;
        }

        [AllowAnonymous]
        [HttpGet("Keys")]
        public ActionResult<List<string>> GenerateKeys()
        {
            var keys = new List<string>();

            using(RSA rsa = RSA.Create())
            {
                keys.Add("---Private Key---");
                keys.Add(Convert.ToBase64String(rsa.ExportRSAPrivateKey()));
                keys.Add("---Public Key---");
                keys.Add(Convert.ToBase64String(rsa.ExportRSAPublicKey()));
            }

            return Ok(keys);
        }

        [AllowAnonymous]
        [HttpGet("Token")]
        public ActionResult<string> GetToken()
        {
            var privateKey = _config["JWT:Keys:Private"];

            using(RSA rsa = RSA.Create())
            {
                rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKey), out int _);

                var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
                {
                    CryptoProviderFactory = new CryptoProviderFactory(){ CacheSignatureProviders = false }
                };

                var jwtDate = DateTime.Now;

                var jwt = new JwtSecurityToken(
                    audience: "jwt-test",
                    issuer: "jwt-test",

                    claims: new List<Claim>() { new Claim(ClaimTypes.NameIdentifier, "DAVIESM")},

                    notBefore: jwtDate,

                    expires: jwtDate.AddHours(1),

                    signingCredentials: signingCredentials
                );

                // generate string token
                string token = new JwtSecurityTokenHandler().WriteToken(jwt);

                return token;

            }
        }

        [Authorize]
        [HttpGet]
        public ActionResult TestToken()
        {
            var user = User;
            return Ok();
        }
    }
}