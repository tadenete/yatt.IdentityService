namespace IdentityService.Models;
using System.Text.Json.Serialization;
public class AuthenticateResponse
{
    public string access { get; set; }
    public string refresh { get; set; }
}