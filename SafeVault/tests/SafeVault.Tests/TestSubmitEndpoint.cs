using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace SafeVault.Tests;

/// <summary>
/// End-to-end attack simulations: real HTTP requests sent to the running app,
/// the way an attacker would send them (bypassing the browser's HTML5 checks).
/// </summary>
[TestFixture]
public class TestSubmitEndpoint
{
    private SafeVaultFactory _factory = null!;
    private HttpClient _client = null!;

    [OneTimeSetUp]
    public void OneTimeSetUp()
    {
        _factory = new SafeVaultFactory();
        _client = _factory.CreateBrowser();
    }

    [OneTimeTearDown]
    public void OneTimeTearDown()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    [Test]
    public async Task ValidSubmission_RegistersUser()
    {
        var response = await _client.RegisterAsync("valid_user", "valid@example.com");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(body, Does.Contain("Welcome, valid_user!"));
            Assert.That(_factory.Users.GetUserByUsername("valid_user"), Is.Not.Null);
        });
    }

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.SqlInjectionPayloads))]
    public async Task SqlInjectionInForm_IsRejectedAndNothingIsStored(string payload)
    {
        var countBefore = _factory.Users.CountUsers();

        var usernameAttack = await _client.RegisterAsync(payload, "attacker@example.com");
        var emailAttack = await _client.RegisterAsync("attacker", payload);

        Assert.Multiple(() =>
        {
            Assert.That(usernameAttack.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(emailAttack.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(_factory.Users.CountUsers(), Is.EqualTo(countBefore));
        });
    }

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.XssPayloads))]
    public async Task XssInForm_IsRejectedAndNotReflected(string payload)
    {
        var response = await _client.RegisterAsync(payload, "xss@example.com");
        var body = await response.Content.ReadAsStringAsync();

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
            Assert.That(body, Does.Not.Contain(payload), "Raw payload must not be echoed back.");
            Assert.That(body, Does.Not.Contain("<script>alert"));
            Assert.That(body, Does.Not.Contain("onerror="));
        });
    }

    [Test]
    public async Task DuplicateUsername_IsRejected()
    {
        await _client.RegisterAsync("dupe_user", "dupe1@example.com");

        var response = await _client.RegisterAsync("DUPE_USER", "dupe2@example.com");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
    }

    [TestCaseSource(typeof(TestInputValidation), nameof(TestInputValidation.SqlInjectionPayloads))]
    public async Task SearchWithInjectionPayload_ReturnsNoUsers(string payload)
    {
        using var client = await _factory.LoginAsAsync($"searcher_{Guid.NewGuid():N}"[..20]);

        var response = await client.GetAsync($"/users/search?q={Uri.EscapeDataString(payload)}");

        // Long payloads are rejected by the length check (400); shorter ones reach the
        // parameterized query and must match nothing. Either way, no user data comes back.
        if (response.StatusCode == HttpStatusCode.BadRequest)
        {
            Assert.That(payload, Has.Length.GreaterThan(30));
            return;
        }

        var results = await response.Content.ReadFromJsonAsync<JsonElement[]>();
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(results, Is.Empty);
    }

    [Test]
    public async Task Search_DoesNotExposeEmailAddresses()
    {
        using var client = await _factory.LoginAsAsync("private_user");

        var body = await client.GetStringAsync("/users/search?q=private");

        Assert.That(body, Does.Contain("private_user"));
        Assert.That(body, Does.Not.Contain("private_user@example.com"));
    }

    [Test]
    public async Task Responses_IncludeSecurityHeaders()
    {
        var response = await _client.GetAsync("/");

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(), Does.Contain("script-src 'self'"));
            Assert.That(response.Headers.GetValues("X-Content-Type-Options").Single(), Is.EqualTo("nosniff"));
        });
    }
}
