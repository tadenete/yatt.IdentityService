namespace yatt.IdentityService.Entities;
public class UserOrganization
{
    public Guid UserId { get; set; }
    public Guid OrganizationId { get; set; }

    public User User { get; set; }
    public Organization Organization { get; set; }
}