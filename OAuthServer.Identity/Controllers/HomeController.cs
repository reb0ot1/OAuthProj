using Microsoft.AspNetCore.Mvc;
using OAuthServer.Identity.Requests;
using OAuthServer.Identity.Services;

namespace OAuthServer.Identity.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpContextAccessor _contextAccessor;
        private readonly IAuthorizationResultService _authorizationResultService;
        private readonly ICodeStoreService _codeStoreService;

        public HomeController(
            IHttpContextAccessor httpContextAccessor,
            IAuthorizationResultService authorizationResultService,
            ICodeStoreService codeStoreService
            )
        {
            this._contextAccessor = httpContextAccessor;
            this._authorizationResultService = authorizationResultService;
            this._codeStoreService = codeStoreService;
        }

        public IActionResult Authorize(AuthorizationRequest request)
        {
            var result = this._authorizationResultService.AuthorizeRequest(_contextAccessor, request);

            if (result.HasError)
                return RedirectToAction("Error", new { error = result.Error });

            var loginModel = new OpenIdConnectLoginRequest
            {
                RedirectUri = result.RedirectUri,
                Code = result.Code,
                RequestedScopes = result.RequestedScopes,
                Nonce = result.Nonce
            };

            return View("Login", loginModel);
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Login(OpenIdConnectLoginRequest loginRequest)
        {
            // here I have to check if the username and passowrd is correct
            // and I will show you how to integrate the ASP.NET Core Identity
            // With our framework

            var result = this._codeStoreService.UpdateClientDataByCode(
                loginRequest.Code,
                loginRequest.RequestedScopes,
                loginRequest.UserName,
                nonce: loginRequest.Nonce);

            if (result != null)
            {
                loginRequest.RedirectUri = loginRequest.RedirectUri + "&code=" + loginRequest.Code;
                return Redirect(loginRequest.RedirectUri);
            }

            return RedirectToAction("Error", new { error = "invalid_request" });
        }

        public JsonResult Token()
        {
            var result = this._authorizationResultService.GenerateToken(this._contextAccessor);

            if (result.HasError)
                return Json("0");

            return Json(result);
        }

        public IActionResult Error([FromQuery]string error)
        {
            return this.View(error);
        }
    }
}
