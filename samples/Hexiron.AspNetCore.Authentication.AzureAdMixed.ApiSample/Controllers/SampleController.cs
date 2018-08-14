using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.ApiSample.Controllers
{
    [Route("[controller]")]
    public class SampleController : Controller
    {
        private readonly AzureAdOptions _azureAdSettings;

        public SampleController(IOptions<AzureAdOptions> azureSettingsAccessor)
        {
            _azureAdSettings = azureSettingsAccessor.Value;
        }

        [Authorize("read:methods")]
        public IActionResult Index()
        {
            return Ok(_azureAdSettings);
        }
    }
}
