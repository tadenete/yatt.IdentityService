namespace yatt.IdentityService.Authorization;

using Microsoft.Extensions.Options;
using yatt.IdentityService.Helpers;
using yatt.IdentityService.Entities;

public class AuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly AppSettings _appSettings;
    public AuthMiddleware(RequestDelegate next, IOptions<AppSettings> appSettings)
    {
        _next = next;
        _appSettings = appSettings.Value;
    }

    public async Task Invoke(HttpContext context, DataContext dataContext, ITokenUtility tokenUtility)
    {
        var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
        var userId = tokenUtility.ValidateJwtToken(token);
        if (userId != null)
        {
            context.Items["User"] = await dataContext.Users.FindAsync(userId.Value);
        }
        await _next(context);
    }
}