namespace yatt.IdentityService.Models;
using System.ComponentModel.DataAnnotations;
public class ForgotPassordRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

}