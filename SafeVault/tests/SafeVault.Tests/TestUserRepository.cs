using Microsoft.Data.Sqlite;
using SafeVault.Data;

namespace SafeVault.Tests;

/// <summary>
/// Runs SQL injection payloads straight at the repository against a real SQLite database,
/// skipping input validation, to prove the parameterized queries are safe on their own.
/// </summary>
[TestFixture]
public class TestUserRepository
{
    private SqliteConnection _keepAlive = null!;
    private UserRepository _users = null!;

    [SetUp]
    public void SetUp()
    {
        // A shared in-memory database lives as long as at least one connection is open.
        var connectionString = $"Data Source=safevault-{Guid.NewGuid()};Mode=Memory;Cache=Shared";
        _keepAlive = new SqliteConnection(connectionString);
        _keepAlive.Open();

        _users = new UserRepository(connectionString);
        _users.EnsureSchema();
        _users.AddUser("alice", "alice@example.com", "not-a-real-hash");
        _users.AddUser("bob", "bob@example.com", "not-a-real-hash");
    }

    [TearDown]
    public void TearDown() => _keepAlive.Dispose();

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.SqlInjectionPayloads))]
    public void Lookup_WithInjectionPayload_ReturnsNoUser(string payload)
    {
        // A vulnerable query built by concatenation would return alice for "' OR '1'='1".
        Assert.That(_users.GetUserByUsername(payload), Is.Null);
        Assert.That(_users.GetUserByEmail(payload), Is.Null);
    }

    [Test]
    public void Lookup_WithCommentPayload_DoesNotBypassMatch()
    {
        Assert.That(_users.GetUserByUsername("alice' --"), Is.Null);
        Assert.That(_users.GetUserByUsername("alice"), Is.Not.Null);
    }

    [Test]
    public void Insert_WithDropTablePayload_StoresTextAndKeepsTable()
    {
        const string payload = "'; DROP TABLE Users; --";

        _users.AddUser(payload, "attacker@example.com", "not-a-real-hash");

        Assert.Multiple(() =>
        {
            Assert.That(_users.CountUsers(), Is.EqualTo(3), "Users table should still exist with all rows.");
            Assert.That(_users.GetUserByUsername(payload)?.Username, Is.EqualTo(payload),
                "Payload should be stored as plain text.");
        });
    }

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.SqlInjectionPayloads))]
    public void Search_WithInjectionPayload_ReturnsNothing(string payload)
    {
        Assert.That(_users.SearchByUsername(payload), Is.Empty);
    }

    [TestCase("%")]
    [TestCase("_")]
    [TestCase("%%")]
    public void Search_WithLikeWildcards_MatchesLiterally(string wildcard)
    {
        Assert.That(_users.SearchByUsername(wildcard), Is.Empty);
    }

    [Test]
    public void Search_WithNormalTerm_FindsMatches()
    {
        var results = _users.SearchByUsername("ali");

        Assert.That(results.Select(u => u.Username), Is.EqualTo(new[] { "alice" }));
    }
}
