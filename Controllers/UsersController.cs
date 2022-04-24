namespace IdentityService.Controllers;

using IdentityService.Services;
using IdentityService.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using IdentityService.Helpers;
using IdentityService.Authorization;
using IdentityService.Entities;
using AutoMapper;

[Authorize]
[ApiController]
[Route("/")]
public class UsersController : BaseController
{
    private readonly IUserService _userService;
    private readonly AppSettings _optionSettings;
    private readonly IMapper _mapper;
    public UsersController(IUserService userService, IOptions<AppSettings> optionSettings, IMapper mapper)
    {
        _userService = userService;
        _optionSettings = optionSettings.Value;
        _mapper = mapper;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult Register(RegisterRequest model)
    {
        var response = _userService.Register(model, Request.Headers["origin"]);
        return Ok(new { message = response });
    }

    [AllowAnonymous]
    [HttpPost("email/verify")]
    public IActionResult VerifyEmail(VerifyEmailRequest model)
    {
        _userService.VerifyEmail(model.Token);
        return Ok(new { message = "Verification successful, you can now login." });
    }

    [HttpGet("/{id}")]
    public IActionResult Get(Guid Id)
    {
        var response = _userService.GetUser(Id);
        return Ok(response);
    }

    [HttpGet("current")]
    public IActionResult Get()
    {
        var currentUserResponse = _mapper.Map<UserResponse>(CurrentUser);
        return Ok(new { currentUser = currentUserResponse });
    }

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
        return Ok(new { message = "Remove role successful." });
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public ActionResult<AuthenticateResponse> Authenticate(AuthenticateRequest model)
    {
        var response = _userService.Authenticate(model, ipAddress());
        //setTokenCookie(response.refreshToken);
        return Ok(response);
    }

    [AllowAnonymous]
    [HttpPost("password/forgot")]
    public IActionResult ForgotPassword(ForgotPassordRequest model)
    {
        _userService.ForgotPassword(model, Request.Headers["origin"]);
        return Ok(new { message = "please check email for password reset instructions" });
    }

    [AllowAnonymous]
    [HttpPost("password/reset")]
    public IActionResult ResetPassword(ResetPasswordRequest model)
    {
        _userService.ResetPassword(model);
        return Ok(new { message = "Password reset successful, you can now login" });
    }

    [AllowAnonymous]
    [HttpPost("refresh")]
    public ActionResult<AuthenticateResponse> RefreshToken(RefreshTokenRequest model)
    {
        var response = _userService.RefreshToken(model.refreshToken, ipAddress());
        return Ok(response);
    }

    [HttpPost("revoke")]
    public IActionResult RevokeToken(RefreshTokenRequest model)
    {
        var token = model.refreshToken ?? Request.Cookies["refreshToken"];
        if (string.IsNullOrEmpty(token))
            return BadRequest(new { message = "Token is required." });

        if (!CurrentUser.OwnsToken(model.refreshToken) && CurrentUser.Role != Role.OrgAdmin)
            return Unauthorized(new { message = "Unauthorized" });

        _userService.RevokeToken(model.refreshToken, ipAddress());
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