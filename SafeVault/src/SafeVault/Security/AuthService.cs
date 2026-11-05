using Microsoft.Data.Sqlite;
using SafeVault.Data;

namespace SafeVault.Security;

public enum LoginStatus { Success, InvalidCredentials, LockedOut }

public sealed record LoginResult(LoginStatus Status, UserSession? Session = null)
{
    public User? User => Session?.User;
}

public sealed record RegistrationResult(User? User, IReadOnlyList<string> Errors, bool IsDuplicate = false)
{
    public bool Succeeded => User is not null;
}

public sealed class AuthService(UserRepository users, PasswordHasher hasher, TimeProvider time)
{
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);

    /// <summary>
    /// Registers a new account. The role is set by the caller (the server), never by the form,
    /// so a user can't make themselves an admin by adding a "role" field to the request.
    /// </summary>
    public RegistrationResult Register(
        string? username, string? email, string? password, string? confirmPassword, string role = Roles.User)
    {
        var name = InputValidator.ValidateUsername(username);
        var mail = InputValidator.ValidateEmail(email);
        var pass = InputValidator.ValidatePassword(password, name.IsValid ? name.Value : null);

        var errors = new[] { name.Error, mail.Error, pass.Error }.OfType<string>().ToList();
        if (pass.IsValid && password != confirmPassword)
            errors.Add("Passwords do not match.");
        if (!Roles.IsValid(role))
            errors.Add("Unknown role.");
        if (errors.Count > 0)
            return new RegistrationResult(null, errors);

        if (users.GetUserByUsername(name.Value) is not null || users.GetUserByEmail(mail.Value) is not null)
            return Duplicate();

        try
        {
            var userId = users.AddUser(name.Value, mail.Value, hasher.Hash(pass.Value), role);
            return new RegistrationResult(users.GetUserById(userId), []);
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) // UNIQUE constraint: lost a race with another signup
        {
            return Duplicate();
        }

        static RegistrationResult Duplicate() =>
            new(null, ["That username or email is already registered."], IsDuplicate: true);
    }

    public LoginResult Login(string? username, string? password)
    {
        var name = InputValidator.ValidateUsername(username);
        var credentials = name.IsValid ? users.GetCredentials(name.Value) : null;

        if (credentials is null)
        {
            hasher.VerifyDummy(password);
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        var now = time.GetUtcNow();
        if (credentials.LockoutEnd > now)
        {
            hasher.VerifyDummy(password);
            return new LoginResult(LoginStatus.LockedOut);
        }

        if (!hasher.Verify(password, credentials.PasswordHash))
        {
            users.RecordFailedLogin(credentials.UserId, MaxFailedAttempts, now + LockoutDuration);
            var lockedNow = credentials.FailedLoginAttempts + 1 >= MaxFailedAttempts;
            return new LoginResult(lockedNow ? LoginStatus.LockedOut : LoginStatus.InvalidCredentials);
        }

        users.ResetFailedLogins(credentials.UserId);

        // If the work factor has been raised since this hash was made, upgrade it now
        // while we have the plain-text password in hand.
        if (hasher.NeedsRehash(credentials.PasswordHash))
            users.UpdatePasswordHash(credentials.UserId, hasher.Hash(password!));

        return new LoginResult(LoginStatus.Success, users.GetSession(credentials.UserId));
    }

    /// <summary>Returns an error message, or null on success.</summary>
    public string? ChangeRole(long actingUserId, long targetUserId, string? role)
    {
        if (!Roles.IsValid(role))
            return "Unknown role.";

        // Stops an admin from accidentally removing their own access (and leaving no admins).
        if (actingUserId == targetUserId)
            return "You cannot change your own role.";

        return users.SetRole(targetUserId, role!) ? null : "User not found.";
    }
}
