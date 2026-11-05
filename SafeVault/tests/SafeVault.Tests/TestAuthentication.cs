using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Time.Testing;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

/// <summary>Login, password hashing and lockout, tested directly against AuthService and a real database.</summary>
[TestFixture]
public class TestAuthentication
{
    private const string Password = SafeVaultFactory.Password;

    private SqliteConnection _keepAlive = null!;
    private UserRepository _users = null!;
    private FakeTimeProvider _clock = null!;
    private AuthService _auth = null!;

    [SetUp]
    public void SetUp()
    {
        var connectionString = $"Data Source=auth-{Guid.NewGuid()};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();

        _users = new UserRepository(connectionString);
        _users.EnsureSchema();
        _clock = new FakeTimeProvider(DateTimeOffset.UtcNow);
        _auth = new AuthService(_users, new PasswordHasher(workFactor: 4), _clock);

        _auth.Register("alice", "alice@example.com", Password, Password);
    }

    [TearDown]
    public void TearDown() => _keepAlive.Dispose();

    // ---- Password hashing ----

    [Test]
    public void Register_StoresBcryptHash_NotPlainText()
    {
        var hash = _users.GetCredentials("alice")!.PasswordHash;

        Assert.Multiple(() =>
        {
            Assert.That(hash, Does.Not.Contain(Password));
            Assert.That(hash, Does.StartWith("$2"), "Expected a bcrypt hash ($2a$/$2b$...).");
            Assert.That(new PasswordHasher(4).Verify(Password, hash), Is.True);
        });
    }

    [Test]
    public void SamePassword_ProducesDifferentHashes_BecauseOfSalt()
    {
        _auth.Register("bob", "bob@example.com", Password, Password);

        Assert.That(_users.GetCredentials("bob")!.PasswordHash,
            Is.Not.EqualTo(_users.GetCredentials("alice")!.PasswordHash));
    }

    [Test]
    public void Verify_WithCorruptHash_ReturnsFalseInsteadOfThrowing()
    {
        Assert.That(new PasswordHasher(4).Verify(Password, "not-a-bcrypt-hash"), Is.False);
    }

    // ---- Login ----

    [Test]
    public void Login_WithCorrectPassword_Succeeds()
    {
        var result = _auth.Login("alice", Password);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.Success));
        Assert.That(result.User!.Username, Is.EqualTo("alice"));
        Assert.That(result.User.Role, Is.EqualTo(Roles.User));
    }

    [Test]
    public void Login_UsernameIsCaseInsensitive()
    {
        Assert.That(_auth.Login("ALICE", Password).Status, Is.EqualTo(LoginStatus.Success));
    }

    [TestCase("wrong-password-123")]
    [TestCase("correct-horse-battery-9")] // passwords are case-sensitive
    [TestCase("Correct-Horse-Battery-9 ")] // and not trimmed
    [TestCase("")]
    [TestCase(null)]
    public void Login_WithWrongPassword_Fails(string? password)
    {
        var result = _auth.Login("alice", password);

        Assert.That(result.Status, Is.EqualTo(LoginStatus.InvalidCredentials));
        Assert.That(result.User, Is.Null);
    }

    [TestCase("nobody")]
    [TestCase("")]
    [TestCase(null)]
    public void Login_WithUnknownUser_Fails(string? username)
    {
        Assert.That(_auth.Login(username, Password).Status, Is.EqualTo(LoginStatus.InvalidCredentials));
    }

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.SqlInjectionPayloads))]
    public void Login_WithSqlInjection_Fails(string payload)
    {
        Assert.Multiple(() =>
        {
            Assert.That(_auth.Login(payload, Password).Status, Is.EqualTo(LoginStatus.InvalidCredentials));
            Assert.That(_auth.Login("alice", payload).Status, Is.EqualTo(LoginStatus.InvalidCredentials));
        });
    }

    // ---- Brute-force protection ----

    [Test]
    public void Login_LocksAccount_AfterFiveFailedAttempts()
    {
        for (var attempt = 1; attempt < AuthService.MaxFailedAttempts; attempt++)
            Assert.That(_auth.Login("alice", "wrong-password-123").Status, Is.EqualTo(LoginStatus.InvalidCredentials));

        Assert.That(_auth.Login("alice", "wrong-password-123").Status, Is.EqualTo(LoginStatus.LockedOut));

        // Even the correct password is refused while locked.
        Assert.That(_auth.Login("alice", Password).Status, Is.EqualTo(LoginStatus.LockedOut));
    }

    [Test]
    public void Lockout_Expires_AfterFifteenMinutes()
    {
        for (var attempt = 0; attempt < AuthService.MaxFailedAttempts; attempt++)
            _auth.Login("alice", "wrong-password-123");

        _clock.Advance(AuthService.LockoutDuration - TimeSpan.FromSeconds(1));
        Assert.That(_auth.Login("alice", Password).Status, Is.EqualTo(LoginStatus.LockedOut));

        _clock.Advance(TimeSpan.FromSeconds(2));
        Assert.That(_auth.Login("alice", Password).Status, Is.EqualTo(LoginStatus.Success));
    }

    [Test]
    public void SuccessfulLogin_ResetsFailedAttemptCounter()
    {
        for (var attempt = 0; attempt < AuthService.MaxFailedAttempts - 1; attempt++)
            _auth.Login("alice", "wrong-password-123");

        Assert.That(_auth.Login("alice", Password).Status, Is.EqualTo(LoginStatus.Success));

        for (var attempt = 0; attempt < AuthService.MaxFailedAttempts - 1; attempt++)
            _auth.Login("alice", "wrong-password-123");

        Assert.That(_auth.Login("alice", Password).Status, Is.EqualTo(LoginStatus.Success));
    }

    [Test]
    public void Login_UpgradesHash_WhenWorkFactorIsRaised()
    {
        var stronger = new AuthService(_users, new PasswordHasher(workFactor: 5), _clock);

        Assert.That(stronger.Login("alice", Password).Status, Is.EqualTo(LoginStatus.Success));
        Assert.That(_users.GetCredentials("alice")!.PasswordHash, Does.StartWith("$2a$05$").Or.StartWith("$2b$05$"));
    }

    // ---- Registration ----

    [TestCase("short", "Password must be at least 12 characters.")]
    [TestCase("password1234", "This password is too common. Choose a less predictable one.")]
    [TestCase("my-name-is-carol!", "Password must not contain your username.")]
    public void Register_RejectsWeakPasswords(string password, string expectedError)
    {
        var result = _auth.Register("carol", "carol@example.com", password, password);

        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Errors, Does.Contain(expectedError));
        Assert.That(_users.GetUserByUsername("carol"), Is.Null);
    }

    [Test]
    public void Register_RejectsMismatchedConfirmation()
    {
        var result = _auth.Register("carol", "carol@example.com", Password, Password + "x");

        Assert.That(result.Errors, Does.Contain("Passwords do not match."));
    }

    [Test]
    public void Register_RejectsDuplicateUsername()
    {
        var result = _auth.Register("Alice", "other@example.com", Password, Password);

        Assert.That(result.IsDuplicate, Is.True);
    }

    [Test]
    public void Register_DefaultsToUserRole()
    {
        Assert.That(_users.GetUserByUsername("alice")!.Role, Is.EqualTo(Roles.User));
    }

    [Test]
    public void Register_RejectsUnknownRole()
    {
        var result = _auth.Register("carol", "carol@example.com", Password, Password, role: "superadmin");

        Assert.That(result.Errors, Does.Contain("Unknown role."));
    }

    // ---- Role assignment ----

    [Test]
    public void ChangeRole_PromotesUser()
    {
        var admin = _auth.Register("root", "root@example.com", Password, Password, Roles.Admin).User!;
        var alice = _users.GetUserByUsername("alice")!;

        Assert.That(_auth.ChangeRole(admin.UserId, alice.UserId, Roles.Admin), Is.Null);
        Assert.That(_users.GetUserById(alice.UserId)!.Role, Is.EqualTo(Roles.Admin));
    }

    [Test]
    public void ChangeRole_RejectsOwnAccount_UnknownRole_AndMissingUser()
    {
        var admin = _auth.Register("root", "root@example.com", Password, Password, Roles.Admin).User!;
        var alice = _users.GetUserByUsername("alice")!;

        Assert.Multiple(() =>
        {
            Assert.That(_auth.ChangeRole(admin.UserId, admin.UserId, Roles.User), Is.EqualTo("You cannot change your own role."));
            Assert.That(_auth.ChangeRole(admin.UserId, alice.UserId, "superadmin"), Is.EqualTo("Unknown role."));
            Assert.That(_auth.ChangeRole(admin.UserId, 9999, Roles.Admin), Is.EqualTo("User not found."));
            Assert.That(_users.GetUserById(admin.UserId)!.Role, Is.EqualTo(Roles.Admin));
        });
    }
}
