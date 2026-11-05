using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Data;

namespace SafeVault.Security;

/// <summary>Converts between a <see cref="User"/> and the claims stored in the login cookie.</summary>
public static class UserPrincipal
{
    private const string SecurityStampClaim = "SafeVault:SecurityStamp";

    public static ClaimsPrincipal Create(UserSession session) => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.NameIdentifier, session.User.UserId.ToString(CultureInfo.InvariantCulture)),
            new Claim(ClaimTypes.Name, session.User.Username),
            new Claim(ClaimTypes.Role, session.User.Role),
            new Claim(SecurityStampClaim, session.SecurityStamp),
        ],
        CookieAuthenticationDefaults.AuthenticationScheme));

    public static long GetUserId(ClaimsPrincipal principal) =>
        TryGetUserId(principal, out var userId)
            ? userId
            : throw new InvalidOperationException("The signed-in user has no valid user ID claim.");

    /// <summary>
    /// Runs on every request that carries a login cookie. The cookie is a snapshot from login time,
    /// so this re-checks the database and rejects the cookie immediately if the account was deleted,
    /// its role changed (e.g. an admin was demoted), or its security stamp changed (the user logged
    /// out, which also kills any copies of the cookie an attacker may have stolen).
    /// </summary>
    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var users = context.HttpContext.RequestServices.GetRequiredService<UserRepository>();
        var principal = context.Principal;
        var session = principal is not null && TryGetUserId(principal, out var userId)
            ? users.GetSession(userId)
            : null;

        if (session is null
            || !principal!.IsInRole(session.User.Role)
            || principal.FindFirstValue(SecurityStampClaim) != session.SecurityStamp)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }

    private static bool TryGetUserId(ClaimsPrincipal principal, out long userId) =>
        long.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), NumberStyles.None,
            CultureInfo.InvariantCulture, out userId);
}
