using System.Net;
using SafeVault.Security;

namespace SafeVault.Tests;

/// <summary>
/// Activity 3 attack simulations: every SQL injection and XSS payload is sent through every
/// field of every form, and stored payloads are checked when they are read back and reused.
/// </summary>
[TestFixture]
public class TestAttackScenarios
{
    private static readonly string[] RegistrationFields = ["username", "email", "password", "confirmPassword"];

    private static IEnumerable<TestCaseData> AllPayloads() =>
        TestInputValidation.SqlInjectionPayloads.Select(p => new TestCaseData(p).SetArgDisplayNames("SQL", p))
            .Concat(TestInputValidation.XssPayloads.Select(p => new TestCaseData(p).SetArgDisplayNames("XSS", p)));

    private SafeVaultFactory _factory = null!;
    private HttpClient _client = null!;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _factory = new SafeVaultFactory();
        _client = _factory.CreateBrowser();
        _factory.CreateUser("alice");
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [TestCaseSource(nameof(AllPayloads))]
    public async Task Registration_EveryField_IsSafe(string payload)
    {
        foreach (var field in RegistrationFields)
        {
            var fields = new Dictionary<string, string>
            {
                ["username"] = $"user_{Guid.NewGuid():N}"[..20],
                ["email"] = $"{Guid.NewGuid():N}@example.com",
                ["password"] = SafeVaultFactory.Password,
                ["confirmPassword"] = SafeVaultFactory.Password,
            };
            fields[field] = payload;
            if (field == "password")
                fields["confirmPassword"] = payload;

            var response = await _client.PostFormAsync("/submit", fields);
            var body = await response.Content.ReadAsStringAsync();

            Assert.Multiple(() =>
            {
                // Passwords may legitimately contain "<" or quotes: they are hashed, never displayed.
                // Every other field must be rejected.
                if (field is not ("password" or "confirmPassword"))
                    Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest), $"{field} accepted: {payload}");
                Assert.That((int)response.StatusCode, Is.LessThan(500), $"{field} caused a server error.");
                Assert.That(body, Does.Not.Contain(payload), $"{field} payload was reflected.");
            });
        }

        Assert.That(_factory.Users.GetUserByUsername("alice"), Is.Not.Null, "Users table must survive.");
    }

    [TestCaseSource(nameof(AllPayloads))]
    public async Task Login_EveryField_IsSafe(string payload)
    {
        var asUsername = await _client.LoginAsync(payload, SafeVaultFactory.Password);
        var asPassword = await _client.LoginAsync("alice", payload);

        foreach (var response in new[] { asUsername, asPassword })
        {
            var body = await response.Content.ReadAsStringAsync();
            Assert.Multiple(() =>
            {
                Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
                Assert.That(body, Does.Not.Contain(payload));
                Assert.That(response.Headers.Contains("Set-Cookie") &&
                    response.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("__Host-SafeVault=")), Is.False);
            });
        }

        // Undo the failed attempts so alice isn't locked out for the next test case.
        _factory.Users.ResetFailedLogins(_factory.Users.GetUserByUsername("alice")!.UserId);
    }

    [TestCase("")]
    [TestCase("\0\0\0")]
    [TestCase("﻿‮​")]                   // BOM, right-to-left override, zero-width space
    [TestCase("𝓪𝓭𝓶𝓲𝓷")]                               // mathematical letters that normalize to "admin"
    public async Task UnusualInput_NeverCausesServerError(string input)
    {
        var register = await _client.RegisterAsync(input, input, input, input);
        var login = await _client.LoginAsync(input, input);

        Assert.That((int)register.StatusCode, Is.LessThan(500));
        Assert.That((int)login.StatusCode, Is.LessThan(500));
    }

    [Test]
    public async Task NullBytes_InAuthenticatedForms_AreRejectedNotCrashing()
    {
        var target = _factory.CreateUser("nullbyte_target");
        using var admin = await _factory.LoginAsAsync("nullbyte_admin", Roles.Admin);
        var token = await admin.GetAntiforgeryTokenAsync("/dashboard");

        var roleChange = await admin.PostFormAsync($"/admin/users/{target.UserId}/role",
            new Dictionary<string, string> { ["role"] = "\0", ["__RequestVerificationToken"] = token });
        var logout = await admin.PostFormAsync("/logout",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token + "\0" });

        Assert.That(roleChange.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task OversizedInput_NeverCausesServerError()
    {
        var huge = new string('A', 100_000);

        var register = await _client.RegisterAsync(huge, huge, huge, huge);
        var login = await _client.LoginAsync(huge, huge);

        Assert.That(register.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(login.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task SearchJson_EscapesStoredScript()
    {
        // Stored directly in the database, as if it came from an older version of the app.
        _factory.Users.AddUser("<script>alert('json')</script>", "json-xss@example.com", "not-a-real-hash");
        using var client = await _factory.LoginAsAsync("searcher");

        var response = await client.GetAsync("/users/search?q=script");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.Content.Headers.ContentType?.MediaType, Is.EqualTo("application/json"));
            Assert.That(body, Does.Not.Contain("<script>"));
            Assert.That(body, Does.Contain("\\u003Cscript\\u003E"));
        });
    }

    [Test]
    public void SecondOrderSqlInjection_StoredPayloadIsHarmlessWhenReused()
    {
        // A payload saved now and used later in another query (second-order injection).
        const string stored = "x' OR '1'='1";
        var users = _factory.Users;
        var id = users.AddUser(stored, "second-order@example.com", "not-a-real-hash");
        var countBefore = users.CountUsers();

        var readBack = users.GetUserById(id)!;
        var matches = users.SearchByUsername(readBack.Username);
        var lookedUp = users.GetUserByUsername(readBack.Username);
        users.SetRole(readBack.UserId, Roles.Admin);

        Assert.Multiple(() =>
        {
            Assert.That(matches.Select(u => u.UserId), Is.EqualTo(new[] { id }), "Must match only the stored row.");
            Assert.That(lookedUp?.UserId, Is.EqualTo(id));
            Assert.That(users.GetUserByUsername("alice")!.Role, Is.EqualTo(Roles.User), "No other row may change.");
            Assert.That(users.CountUsers(), Is.EqualTo(countBefore));
        });
    }
}
