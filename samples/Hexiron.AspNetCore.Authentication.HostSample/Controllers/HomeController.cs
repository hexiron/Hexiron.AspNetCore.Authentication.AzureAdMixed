using Hexiron.Azure.ActiveDirectory.Connectors.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Hexiron.AspNetCore.Authentication.HostSample.Controllers
{
    public class HomeController : Controller
    {
        private readonly IAzureAdB2CSecuredApiConnector _b2CConnector;

        public HomeController(IAzureAdB2CSecuredApiConnector b2CConnector)
        {
            _b2CConnector = b2CConnector;
        }

        public IActionResult Index()
        {
            // get something from api
            _b2CConnector.Get<object>("");
            return View();
        }
    }
}
