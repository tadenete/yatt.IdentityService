namespace yatt.IdentityService.Entities;
using System.ComponentModel.DataAnnotations;
public class Organization
{
    [Key]
    public Guid Id { get; set; }
    public IList<UserOrganization> IdentityOrganizations { get; set; }
}