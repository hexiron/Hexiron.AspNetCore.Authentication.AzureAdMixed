using Hexiron.AspNetCore.Authentication.AzureAdMixed.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Sample.Controllers
{
    [Route("[controller]")]
    public class SampleController : Controller
    {
        private readonly AzureAuthenticationSettings _azureSettings;

        public SampleController(IOptions<AzureAuthenticationSettings> azureSettingsAccessor)
        {
            _azureSettings = azureSettingsAccessor.Value;
        }

        [Authorize("read:methods")]
        public IActionResult Index()
        {
            return Ok(_azureSettings);
        }
    }
}
