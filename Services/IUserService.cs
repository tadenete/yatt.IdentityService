namespace IdentityService.Services;

using IdentityService.Models;
using IdentityService.Entities;
using IdentityService.Authorization;
using IdentityService.Helpers;
using Microsoft.EntityFrameworkCore;
using AutoMapper;
using BCrypt.Net;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

public interface IUserService
{
    void Register(RegisterRequest model, string origin);
    void VerifyEmail(string token);
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    void ResetPassword(ResetPasswordRequest model);
    void ForgotPassword(ForgotPassordRequest model, string origin);
    void AddRole(UpdateRoleRequest model);
    void RemoveRole(UpdateRoleRequest model);
    AuthenticateResponse RefreshToken(string token, string ipAddress);
    void RevokeToken(string token, string ipAddress);

    UserResponse GetUser(Guid Id);
}

public class UserService : IUserService
{
    private readonly DataContext _context;
    private readonly ITokenUtility _tokenUtility;
    private readonly IMapper _mapper;
    private readonly AppSettings _appSettings;
    private readonly IEmailService _emailService;
    public UserService(DataContext context,
                ITokenUtility tokenUtility,
                IMapper mapper,
                IOptions<AppSettings> appSettings,
                IEmailService emailService)
    {
        _context = context;
        _tokenUtility = tokenUtility;
        _mapper = mapper;
        _appSettings = appSettings.Value;
        _emailService = emailService;
    }

    public void Register(RegisterRequest model, string origin)
    {
        if (_context.Users.Any(x => x.Email == model.Email))
        {
            //send already registered email
            sendAlreadyRegisteredEmail(model.Email, origin);
            return;
        }
        var user = _mapper.Map<User>(model);
        user.Created = DateTime.UtcNow;

        //generate token for account verification.
        user.VerificationToken = generateVerificationToken();
        user.PasswordHash = BCrypt.HashPassword(model.Password);

        _context.Users.Add(user);
        _context.SaveChanges();

        //send email
        sendVerificationEmail(user, origin);

    }
    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipaddress)
    {
        var user = _context.Users.SingleOrDefault(x => x.Email == model.Email);

        //validation
        if (user == null || !user.IsVerified || !BCrypt.Verify(model.Password, user.PasswordHash))
            throw new AppException("Email or Password is incorrect");

        //authentication successful, generate jwt and refresh token
        var token = _tokenUtility.GenerateJwtToken(user);
        var refreshToken = _tokenUtility.GenerateRefreshToken(ipaddress);
        user.RefreshTokens.Add(refreshToken);

        //remove old refresh tokens from account
        removeOldRefreshToken(user);

        _context.Update(user);
        _context.SaveChanges();

        return new AuthenticateResponse { token = token, refreshToken = refreshToken.Token };
    }
    public void VerifyEmail(string token)
    {
        var user = _context.Users.SingleOrDefault(x => x.VerificationToken == token);
        if (user == null)
            throw new Exception("Verification failed");
        user.Verified = DateTime.UtcNow;
        user.VerificationToken = null;

        _context.Users.Update(user);
        _context.SaveChanges();
    }

    #region token management
    public AuthenticateResponse RefreshToken(string token, string ipAddress)
    {
        var user = _context.Users.SingleOrDefault(x => x.RefreshTokens.Any(t => t.Token == token));
        if (user == null)
            throw new AppException("Invalid token");
        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        if (refreshToken.IsRevoked)
        {
            // revoke all descendant tokens in case this token has been compromised
            revokeDescendantRefreshTokens(refreshToken, user, ipAddress, $"Attempted reuse of revoked ancestor token: {token}");
            _context.Update(user);
            _context.SaveChanges();
        }

        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        //rotate token.
        var newRefreshToken = rotateRefreshToken(refreshToken, ipAddress);
        user.RefreshTokens.Add(newRefreshToken);

        //remove old refresh tokens from account.
        removeOldRefreshToken(user);

        _context.Update(user);
        _context.SaveChanges();

        //generate new jwt.
        var jwtToken = _tokenUtility.GenerateJwtToken(user);

        //return data in authenticate response object.
        return new AuthenticateResponse { token = token, refreshToken = refreshToken.Token };
    }

    public void RevokeToken(string token, string ipAddress)
    {
        var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(x => x.Token == token));
        if (user == null)
            throw new KeyNotFoundException("Account not found");

        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);
        if (!refreshToken.IsActive)
            throw new AppException("Invalid token");

        revokeRefreshToken(refreshToken, ipAddress, "Revoked without replacement");
        _context.Update(user);
        _context.SaveChanges();
    }

    private RefreshToken rotateRefreshToken(RefreshToken refreshToken, string ipAddress)
    {
        var newRefreshToken = _tokenUtility.GenerateRefreshToken(ipAddress);
        revokeRefreshToken(refreshToken, ipAddress, "Replace by new token", newRefreshToken.Token);
        return newRefreshToken;
    }
    private void revokeDescendantRefreshTokens(RefreshToken refreshToken, User user, string ipAddress, string reason)
    {
        if (!string.IsNullOrEmpty(refreshToken.ReplacedByToken))
        {
            var childToken = user.RefreshTokens.SingleOrDefault(x => x.Token == refreshToken.ReplacedByToken);
            if (childToken.IsActive)
                revokeRefreshToken(childToken, ipAddress, reason);
            else
                revokeDescendantRefreshTokens(childToken, user, ipAddress, reason);
        }
    }

    private void revokeRefreshToken(RefreshToken token, string ipAddress, string reason = null, string replacedByToken = null)
    {
        token.Revoked = DateTime.UtcNow;
        token.RevokedByIp = ipAddress;
        token.ReasonRevoked = reason;
        token.ReplacedByToken = replacedByToken;
    }
    #endregion

    #region password methods
    public void ForgotPassword(ForgotPassordRequest model, string origin)
    {
        var user = _context.Users.SingleOrDefault(x => x.Email == model.Email);
        if (user == null) return;

        //create reset token that expires after 1 day.
        user.ResetToken = generateResetToken();
        user.ResetTokenExpires = DateTime.UtcNow.AddDays(1);

        _context.Users.Update(user);
        _context.SaveChanges();

        sendPasswordResetEmail(user, origin);
    }

    public void ResetPassword(ResetPasswordRequest model)
    {
        var user = _context.Users
            .SingleOrDefault(x => x.ResetToken == model.Token && x.ResetTokenExpires > DateTime.UtcNow);
        if (user == null) throw new AppException("Invalid Password reset token");

        //update password and remove reset token.
        user.PasswordHash = BCrypt.HashPassword(model.Password);
        user.PasswordReset = DateTime.UtcNow;
        user.ResetToken = null;
        user.ResetTokenExpires = null;

        _context.Users.Update(user);
        _context.SaveChanges();
    }


    public UserResponse GetUser(Guid Id)
    {
        var user = _context.Users.Include(y => y.UserOrganizations).SingleOrDefault(x => x.Id == Id);
        if (user == null)
            throw new AppException("User couldn't be found.");
        return _mapper.Map<UserResponse>(user);
    }
    #endregion

    #region manage roles
    public void AddRole(UpdateRoleRequest model)
    {
        var user = _context.Users.SingleOrDefault(x => x.Email == model.Email);
        if (user == null)
            throw new AppException("User email couldn't be found.");

        //check role being added.
        if ((model.Role != Convert.ToString(Role.EventAdmin)
                && model.Role != Convert.ToString(Role.OrgAdmin)))
            throw new AppException("User role is not supported.");

        user.Role = (Role)Enum.Parse(typeof(Role), model.Role);
        var organization = _context.Organizations.SingleOrDefault(x => x.Id == model.OrgId);
        if (organization == null)
            _context.Organizations.Add(new Organization { Id = model.OrgId });

        var userOrganization = _context.UserOrganizations
            .SingleOrDefault(x => x.UserId == user.Id && x.OrganizationId == model.OrgId);

        if (userOrganization == null)
            _context.UserOrganizations.Add(new UserOrganization
            {
                User = user,
                Organization = organization,
                UserId = user.Id,
                OrganizationId = model.OrgId
            });
        user.Updated = DateTime.UtcNow;
        _context.Users.Update(user);
        _context.SaveChanges();
    }

    public void RemoveRole(UpdateRoleRequest model)
    {
        var user = _context.Users.SingleOrDefault(x => x.Email == model.Email);
        if (user == null)
            throw new AppException("User email couldn't be found.");

        //prevent organization admins from being removed.
        if (model.Role == Convert.ToString(Role.OrgAdmin))
            throw new AppException("Organization admins can not be removed.");

        //remove identity-organization link.
        var userOrganization = _context.UserOrganizations.SingleOrDefault(x => x.UserId == user.Id && x.OrganizationId == model.OrgId);
        if (userOrganization == null)
            throw new AppException("Unable to find user role to remove.");
        _context.UserOrganizations.Remove(userOrganization);

        //if the user no longer has access to other companies, deactivate user account.
        if (!_context.UserOrganizations.Any(x => x.UserId == user.Id))
            _context.Users.Remove(user);

        _context.SaveChanges();
    }
    #endregion

    #region private token related methods.
    private string generateResetToken()
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        var tokenIsUnique = !_context.Users.Any(x => x.ResetToken == token);
        if (!tokenIsUnique)
            return generateResetToken();
        return token;
    }
    private string generateVerificationToken()
    {
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(64));
        var tokenIsUnique = !_context.Users.Any(x => x.VerificationToken == token);
        if (!tokenIsUnique)
            return generateVerificationToken();
        return token;
    }
    private void removeOldRefreshToken(User user)
    {
        user.RefreshTokens.RemoveAll(x => !x.IsActive && x.Created.AddDays(_appSettings.RefreshTokenTTL) <= DateTime.UtcNow);
    }
    #endregion

    #region private email methods
    private void sendAlreadyRegisteredEmail(string email, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
            message = $@"<p>If you don't know your password please visit the <a href=""{origin}/account/forgot-password"">forgot password</a> page.</p>";
        else
            message = "<p>If you don't know your password you can reset it via the <code>/accounts/forgot-password</code> api route.</p>";

        _emailService.Send(
            to: email,
            subject: "Sign-up Verification API - Email Already Registered",
            html: $@"<h4>Email Already Registered</h4>
                        <p>Your email <strong>{email}</strong> is already registered.</p>
                        {message}"
        );
    }
    private void sendPasswordResetEmail(User user, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
        {
            var resetUrl = $"{origin}/account/reset-password?token={user.ResetToken}";
            message = $@"<p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                            <p><a href=""{resetUrl}"">{resetUrl}</a></p>";
        }
        else
        {
            message = $@"<p>Please use the below token to reset your password with the <code>/accounts/reset-password</code> api route:</p>
                            <p><code>{user.ResetToken}</code></p>";
        }

        _emailService.Send(
            to: user.Email,
            subject: "Sign-up Verification API - Reset Password",
            html: $@"<h4>Reset Password Email</h4>
                        {message}"
        );
    }
    private void sendVerificationEmail(User user, string origin)
    {
        string message;
        if (!string.IsNullOrEmpty(origin))
        {
            var verifyUrl = $"{origin}/account/verify-email?token={user.VerificationToken}";
            message = $@"<p>Please click the below link to verify your email address:</p>
                            <p><a href=""{verifyUrl}"">{verifyUrl}</a></p>";
        }
        else
        {
            message = $@"<p>Please use the below token to verify your email address with the <code>/accounts/verify-email</code> api route:</p>
                            <p><code>{user.VerificationToken}</code></p>";
        }

        _emailService.Send(
            to: user.Email,
            subject: "Sign-up Verification API - Verify Email",
            html: $@"<h4>Verify Email</h4>
                        <p>Thanks for registering!</p>
                        {message}"
        );
    }
    #endregion
}