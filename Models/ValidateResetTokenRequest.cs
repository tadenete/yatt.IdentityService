namespace IdentityService.Models;
using System.ComponentModel.DataAnnotations;

public class ValidateResetTokenRequest
{
    [Required]
    public string Token { get; set; }
}