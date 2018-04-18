using Hexiron.AspNetCore.Authentication.AzureAdMixed.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Sample.Controllers
{
    [Route("api/{controller}")]
    public class SampleController : Controller
    {
        private readonly AzureB2CSettings _azureB2CSettings;

        public SampleController(IOptions<AzureB2CSettings> azureB2CSettingsAccessor)
        {
            _azureB2CSettings = azureB2CSettingsAccessor.Value;
        }

        [Authorize("read:methods")]
        public IActionResult SecuredMethod()
        {
            return Ok(_azureB2CSettings);
        }
    }
}
