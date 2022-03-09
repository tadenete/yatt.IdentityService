namespace yatt.IdentityService.Controllers;

using Microsoft.AspNetCore.Mvc;
using yatt.IdentityService.Entities;
[Controller]
public abstract class RootController: Controller
{
    public User Identity => (User)HttpContext.Items["User"];
}