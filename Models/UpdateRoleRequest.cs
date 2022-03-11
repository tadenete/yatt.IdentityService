namespace IdentityService.Models;

using System.ComponentModel.DataAnnotations;
public class UpdateRoleRequest
{
    [Required]
    [EmailAddress]
    public string Email { get; set; }

    public Guid OrgId { get; set; }

    [Required]
    public string Role { get; set; }
}