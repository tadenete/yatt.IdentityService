namespace IdentityService.Models;
using System.ComponentModel.DataAnnotations;
public class RegisterRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    [Required]
    public string Password { get; set; }
}