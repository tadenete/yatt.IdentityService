namespace IdentityService.Controllers;

using Microsoft.AspNetCore.Mvc;
using IdentityService.Entities;
[Controller]
public abstract class BaseController: Controller
{
    public User Identity => (User)HttpContext.Items["User"];
}