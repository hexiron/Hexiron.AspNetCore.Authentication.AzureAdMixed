using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Hexiron.AspNetCore.Authentication.UiSample.Controllers
{
    public class AccountController : Controller
    {
        private readonly AzureAdB2COptions _b2COptions;

        public AccountController(IOptions<AzureAdB2COptions> b2COptionsAccessor)
        {
            _b2COptions = b2COptionsAccessor.Value;
        }

        [AllowAnonymous]
        public IActionResult SignIn(string returnUrl = "/")
        {
            var properties = new AuthenticationProperties { RedirectUri = returnUrl };
            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }
        [AllowAnonymous]
        public IActionResult ResetPassword()
        {
            var redirectUrl = Url.Page("/");
            var properties = new AuthenticationProperties { RedirectUri = redirectUrl };
            properties.Items["Policy"] = _b2COptions.ResetPasswordPolicyId;
            return Challenge(properties, OpenIdConnectDefaults.AuthenticationScheme);
        }

        public IActionResult SignOut()
        {
            var callbackUrl = Url.Page("/Account/SignedOut", pageHandler: null, values: null, protocol: Request.Scheme);
            return SignOut(
                new AuthenticationProperties { RedirectUri = callbackUrl },
                CookieAuthenticationDefaults.AuthenticationScheme,
                OpenIdConnectDefaults.AuthenticationScheme
            );
        }
    }
}
