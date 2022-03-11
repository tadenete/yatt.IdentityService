namespace IdentityService.Models;

public class UserResponse
{
    public Guid Id { get; set; }
    public string Email { get; set; }
    public string Role { get; set; }
    public List<Guid> Organizations { get; set; }
}