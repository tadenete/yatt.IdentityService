namespace IdentityService.Models;
using System.ComponentModel.DataAnnotations;

public class ResetPasswordRequest
{
    [Required]
    public string Token { get; set; }

    [Required]
    [MinLength(8)]
    public string Password { get; set; }

    [Required]
    [Compare("Password")]
    public string ConfirmPassword { get; set; }
}