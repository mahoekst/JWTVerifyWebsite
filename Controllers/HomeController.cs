using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using WebApplication2.Models;

namespace WebApplication2.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

         public IActionResult Verify()
        {
            return View(new MessageViewModel());
        }
        [HttpPost]
        public async Task<IActionResult> Verify(MessageViewModel message)
        {
            message.result = "Start Validating";

            SecurityToken parsedToken = null;

            var certid = "https://mahoekstkeyvault.vault.azure.net/certificates/mahoekstsigningcert/433f9ac74bef4213817105287d954ba1";
            var provider = new AzureServiceTokenProvider();
            var kv = new KeyVaultClient(new KeyVaultClient.AuthenticationCallback(provider.KeyVaultTokenCallback));
            var cert = await kv.GetCertificateAsync(certid); //we schould cache this cert for x hours 

            string signedtokentoverify = message.SignedBody;


            X509Certificate2 tokenSigningCert = new X509Certificate2(cert.Cer);

            var validationParameters = new TokenValidationParameters
            {
                ValidAudience = "my custom audience",
                ValidIssuer = "Matthijs",
                IssuerSigningKey = new X509SecurityKey(tokenSigningCert),
                ValidateLifetime = true,
                RequireExpirationTime = true
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                var claimsPrincipal = tokenHandler.ValidateToken(signedtokentoverify, validationParameters, out parsedToken);
                message.Body = parsedToken.ToString();
                message.result = "Validation succesful";
            }
            catch (Exception ex)
            {
                message.result = "ERROR VALIDATING:" + ex.Message;

            }

            return View(message);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
