namespace IdentityService.Models;
public class AuthenticateResponse
{
    public string accessToken { get; set; }
    public string refreshToken { get; set; }
}