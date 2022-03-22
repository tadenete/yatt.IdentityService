namespace IdentityService.Controllers;

using Microsoft.AspNetCore.Mvc;
using IdentityService.Entities;
[Controller]
public abstract class BaseController: Controller
{
    public User CurrentUser => (User)HttpContext.Items["User"];
}