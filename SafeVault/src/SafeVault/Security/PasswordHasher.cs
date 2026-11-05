using System.Text;

namespace SafeVault.Security;

/// <summary>
/// Hashes passwords with bcrypt. Each hash gets its own random salt, which bcrypt stores inside
/// the hash string, so two users with the same password still get different hashes.
/// The work factor makes each guess slow (2^workFactor rounds), which slows down brute-force attacks.
/// </summary>
public sealed class PasswordHasher
{
    public const int DefaultWorkFactor = 12;

    private readonly int _workFactor;
    private readonly string _dummyHash;

    public PasswordHasher(int workFactor = DefaultWorkFactor)
    {
        _workFactor = workFactor;
        _dummyHash = BCrypt.Net.BCrypt.HashPassword(Guid.NewGuid().ToString(), workFactor);
    }

    public string Hash(string password) =>
        BCrypt.Net.BCrypt.HashPassword(Normalize(password), _workFactor);

    public bool Verify(string? password, string hash)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(Normalize(password), hash);
        }
        catch (BCrypt.Net.SaltParseException)
        {
            return false;
        }
    }

    /// <summary>
    /// Does the same amount of work as a real check. Used when the username doesn't exist,
    /// so a failed login takes the same time either way and response timing can't reveal
    /// which usernames are registered.
    /// </summary>
    public void VerifyDummy(string? password) => BCrypt.Net.BCrypt.Verify(Normalize(password), _dummyHash);

    public bool NeedsRehash(string hash) => BCrypt.Net.BCrypt.PasswordNeedsRehash(hash, _workFactor);

    // Passwords are normalized (so the same characters typed on different keyboards match)
    // but never trimmed: spaces are legitimate password characters.
    private static string Normalize(string? password) =>
        (password ?? string.Empty).Normalize(NormalizationForm.FormKC);
}
