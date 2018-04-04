using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Hexiron.AspNetCore.Authentication.AzureAdMixed.Sample.Controllers
{
    [Route("api/{controller}")]
    public class SampleController : Controller
    {
        [Authorize("read:methods")]
        public IActionResult SecuredMethod()
        {
            return Ok();
        }
    }
}
