namespace IdentityService.Entities;
using System.ComponentModel.DataAnnotations;
public class User
{
    [Key]
    public Guid Id { get; set; }
    public string Email { get; set; }
    public Role Role { get; set; }
    public string PasswordHash { get; set; }
    public string VerificationToken { get; set; }
    public DateTime? Verified { get; set; }
    public bool IsVerified => Verified.HasValue || PasswordReset.HasValue;
    public string ResetToken { get; set; }
    public DateTime? ResetTokenExpires { get; set; }
    public DateTime? PasswordReset { get; set; }
    public DateTime Created { get; set; }
    public DateTime? Updated { get; set; }
    public List<RefreshToken> RefreshTokens { get; set; }

    public bool OwnsToken(string token)
    {
      return this.RefreshTokens.Any(x => x.Token == token);
    }
    public IList<UserOrganization> UserOrganizations { get; set; }
}