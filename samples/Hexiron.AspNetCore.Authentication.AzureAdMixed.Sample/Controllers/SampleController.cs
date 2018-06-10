using Hexiron.Azure.ActiveDirectory.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Sample.Controllers
{
    [Route("[controller]")]
    public class SampleController : Controller
    {
        private readonly AzureAdSettings _azureAdSettings;

        public SampleController(IOptions<AzureAdSettings> azureSettingsAccessor)
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
