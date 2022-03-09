namespace yatt.IdentityService.Models;
using System.Text.Json.Serialization;
public class AuthenticateResponse
{
    public string token { get; set; }

    [JsonIgnore] // refresh token is returned in http only cookie.
    public string refreshToken { get; set; }
}