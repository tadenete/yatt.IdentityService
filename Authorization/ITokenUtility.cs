namespace yatt.IdentityService.Authorization;
using yatt.IdentityService.Entities;
using yatt.IdentityService.Helpers;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
public interface ITokenUtility
{
    public string GenerateJwtToken(User user);
    public int? ValidateJwtToken(string token);
    public RefreshToken GenerateRefreshToken(string ipAddress);
}

public class TokenUtility : ITokenUtility
{
    private readonly DataContext _context;
    private readonly AppSettings _appSettings;
    public TokenUtility(DataContext context, IOptions<AppSettings> appSettings)
    {
        _context = context;
        _appSettings = appSettings.Value;
    }
    public string GenerateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] {
                    new Claim(nameof(User.Id), user.Id.ToString()),
                    new Claim(nameof(User.Email), user.Email),
                    new Claim(nameof(UserOrganization.OrganizationId), JsonSerializer.Serialize(user.UserOrganizations?.Select(x => x.OrganizationId))),
                    new Claim(nameof(User.Role), Convert.ToString(user.Role))
                }),
            Expires = DateTime.UtcNow.AddMinutes(_appSettings.AccessTokenTTL),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    public int? ValidateJwtToken(string token)
    {
        if (token == null) return null;
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        try
        {
            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validateToken);
            var jwtToken = (JwtSecurityToken)validateToken;
            return int.Parse(jwtToken.Claims.First(x => x.Type == nameof(User.Id)).Value);
        }
        catch { return null; }
    }
    public RefreshToken GenerateRefreshToken(string ipAddress)
    {
        var refreshToken = new RefreshToken
        {
            Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64)),
            Expires = DateTime.UtcNow.AddDays(_appSettings.RefreshTokenTTL),
            Created = DateTime.UtcNow,
            CreatedByIp = ipAddress
        };

        //ensure token is unique
        var tokenIsUnique = !_context.Users.Any(x => x.RefreshTokens.Any(y => y.Token == refreshToken.Token));
        if (!tokenIsUnique)
            return GenerateRefreshToken(ipAddress);
        return refreshToken;
    }
}