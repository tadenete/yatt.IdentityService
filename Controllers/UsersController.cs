namespace yatt.IdentityService.Controllers;

using yatt.IdentityService.Services;
using yatt.IdentityService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using yatt.IdentityService.Helpers;
using yatt.IdentityService.Authorization;
using yatt.IdentityService.Entities;

[Authorize]
[ApiController]
[Route("[Controller]")]
public class UsersController : RootController
{
    private readonly IUserService _userService;
    private readonly AppSettings _optionSettings;
    public UsersController(IUserService userService, IOptions<AppSettings> optionSettings)
    {
        _userService = userService;
        _optionSettings = optionSettings.Value;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model)
    {
        _userService.Register(model, Request.Headers["origin"]);
        return Ok(new { message = "Registration successful, please check your email for verification instructions." });
    }

    [AllowAnonymous]
    [HttpPost("verify-email")]
    public IActionResult VerifyEmail(VerifyEmailRequest model)
    {
        _userService.VerifyEmail(model.Token);
        return Ok(new { message = "Verification successful, you can now login." });
    }

    [AllowAnonymous]
    [HttpGet("get-user")]
    public IActionResult Get(Guid Id)
    {
        var response = _userService.GetUser(Id);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("assign")]
    public IActionResult AddRole(UpdateRoleRequest model)
    {
        _userService.AddRole(model);
        return Ok(new { message = "Assign role successful." });
    }

    [HttpPost("remove")]
    public IActionResult RemoveRole(UpdateRoleRequest model)
    {
        _userService.RemoveRole(model);
        return Ok(new { message = "Assign role successful." });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
    {
        var response = _userService.Authenticate(model, ipAddress());
        setTokenCookie(response.refreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public IActionResult ForgotPassword(ForgotPassordRequest model)
    {
        _userService.ForgotPassword(model, Request.Headers["origin"]);
        return Ok(new { message = "please check email for password reset instructions" });
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public IActionResult ResetPassword(ResetPasswordRequest model)
    {
        _userService.ResetPassword(model);
        return Ok(new { message = "Password reset successful, you can now login" });
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public ActionResult<AuthenticateResponse> RefreshToken()
    {
        var refreshToken = Request.Cookies["refreshToken"];
        var response = _userService.RefreshToken(refreshToken, ipAddress());
        setTokenCookie(response.refreshToken);
        return Ok(response);
    }

    [HttpPost("revoke")]
    public IActionResult RevokeToken(RevokeTokenRequest model)
    {
        var token = model.Token ?? Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required." });

        if (Identity.OwnsToken(model.Token) && Identity.Role != Role.OrgAdmin)
            return Unauthorized(new { message = "Unauthorized" });

        _userService.RevokeToken(model.Token, ipAddress());
        return Ok(new { message = "Token revoked" });
    }
    private string ipAddress()
    {
        if (Request.Headers.ContainsKey("X-Forwarded-For"))
            return Request.Headers["X-Forwarded-For"];
        else
            return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
    }
    private void setTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddDays(_optionSettings.RefreshTokenTTL)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }
}