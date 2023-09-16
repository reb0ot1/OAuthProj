using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OAuthServer.Client.Controllers
{
    public class HomeController : Controller
    {
        [HttpGet]
        [Authorize]
        public IActionResult Index()
        {
            return this.View();
        }

        [HttpGet]
        public IActionResult TestView()
        {
            return this.View();
        }
    }
}
