using System.Net;

namespace SafeVault.Tests;

/// <summary>
/// Regression tests for the vulnerabilities found in the Activity 3 audit (see SECURITY-SUMMARY.md).
/// Each test was written first, seen to fail against the unfixed code, then passed after the fix.
/// </summary>
[TestFixture]
public class TestSecurityFixes
{
    private SafeVaultFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    private static string LoginCookie(HttpResponseMessage loginResponse) =>
        loginResponse.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-SafeVault=")).Split(';')[0];

    private static async Task<HttpStatusCode> GetDashboardWithCookie(HttpClient client, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/dashboard");
        request.Headers.Add("Cookie", cookie);
        return (await client.SendAsync(request)).StatusCode;
    }

    private static HttpRequestMessage LoginRequest(string username, params (string Name, string Value)[] headers)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "/login")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = username,
                ["password"] = SafeVaultFactory.Password,
            }),
        };
        foreach (var (name, value) in headers)
            request.Headers.Add(name, value);
        return request;
    }

    // ---- SV-01: sessions stayed valid after logout ----

    [Test]
    public async Task SV01_CopiedCookie_IsRejected_AfterLogout()
    {
        _factory.CreateUser("alice");
        using var raw = _factory.CreateBrowser(handleCookies: false);
        var stolenCookie = LoginCookie(await raw.LoginAsync("alice", SafeVaultFactory.Password));
        Assert.That(await GetDashboardWithCookie(raw, stolenCookie), Is.EqualTo(HttpStatusCode.OK));

        // Alice logs out in her own browser.
        using var browser = _factory.CreateBrowser();
        await browser.LoginAsync("alice", SafeVaultFactory.Password);
        var token = await browser.GetAntiforgeryTokenAsync("/dashboard");
        await browser.PostFormAsync("/logout", new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        Assert.That(await GetDashboardWithCookie(raw, stolenCookie), Is.EqualTo(HttpStatusCode.Redirect),
            "A cookie copied before logout must stop working once the user logs out.");
    }

    [Test]
    public async Task SV01_NewLogin_StillWorks_AfterLogout()
    {
        using var client = await _factory.LoginAsAsync("alice");
        var token = await client.GetAntiforgeryTokenAsync("/dashboard");
        await client.PostFormAsync("/logout", new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        await client.LoginAsync("alice", SafeVaultFactory.Password);

        Assert.That((await client.GetAsync("/dashboard")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ---- SV-02: forms accepted cross-site submissions (login CSRF) ----

    [TestCase("Sec-Fetch-Site", "cross-site")]
    [TestCase("Sec-Fetch-Site", "same-site")] // a sibling subdomain is still a different origin
    [TestCase("Origin", "https://evil.example")]
    [TestCase("Origin", "null")]              // sandboxed iframes and some redirects send "null"
    public async Task SV02_CrossSiteFormPost_IsRejected(string header, string value)
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser();

        var response = await client.SendAsync(LoginRequest("alice", (header, value)));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(response.Headers.Contains("Set-Cookie") &&
            response.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("__Host-SafeVault=")), Is.False);
    }

    [Test]
    public async Task SV02_CrossSiteRegistration_IsRejected()
    {
        using var client = _factory.CreateBrowser();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/submit")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["username"] = "victim", ["email"] = "victim@example.com",
                ["password"] = SafeVaultFactory.Password, ["confirmPassword"] = SafeVaultFactory.Password,
            }),
        };
        request.Headers.Add("Sec-Fetch-Site", "cross-site");

        Assert.That((await client.SendAsync(request)).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(_factory.Users.GetUserByUsername("victim"), Is.Null);
    }

    [TestCase("Sec-Fetch-Site", "same-origin")]
    [TestCase("Sec-Fetch-Site", "none")]       // typed into the address bar / bookmark
    [TestCase("Origin", "https://localhost")]
    public async Task SV02_SameOriginFormPost_IsAllowed(string header, string value)
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser();

        var response = await client.SendAsync(LoginRequest("alice", (header, value)));

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task SV02_CrossSiteGet_IsStillAllowed()
    {
        // Links from other sites to public pages must keep working; only state-changing requests are blocked.
        using var client = _factory.CreateBrowser();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/login.html");
        request.Headers.Add("Sec-Fetch-Site", "cross-site");

        Assert.That((await client.SendAsync(request)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ---- SV-03: no rate limiting on login and registration ----

    [Test]
    public async Task SV03_Login_IsRateLimited()
    {
        using var factory = new SafeVaultFactory(accountRequestsPerMinute: 5);
        using var client = factory.CreateBrowser();

        var codes = new List<HttpStatusCode>();
        for (var attempt = 0; attempt < 6; attempt++)
            codes.Add((await client.LoginAsync($"guess{attempt}", "wrong-password-123")).StatusCode);

        Assert.That(codes.Take(5), Is.All.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(codes[5], Is.EqualTo(HttpStatusCode.TooManyRequests));
    }

    [Test]
    public async Task SV03_Registration_IsRateLimited()
    {
        using var factory = new SafeVaultFactory(accountRequestsPerMinute: 3);
        using var client = factory.CreateBrowser();

        for (var i = 0; i < 3; i++)
            await client.RegisterAsync($"bulk_user_{i}", $"bulk{i}@example.com");
        var fourth = await client.RegisterAsync("bulk_user_3", "bulk3@example.com");

        Assert.That(fourth.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
        Assert.That(factory.Users.GetUserByUsername("bulk_user_3"), Is.Null);
    }

    // ---- SV-04: some responses were cacheable / frameable ----

    [TestCase("/users/search?q=ali")]
    [TestCase("/dashboard")]
    public async Task SV04_AuthenticatedResponses_AreNotCached(string path)
    {
        using var client = await _factory.LoginAsAsync("alice");

        var response = await client.GetAsync(path);

        Assert.That(response.Headers.CacheControl?.NoStore, Is.True, $"{path} must send Cache-Control: no-store.");
    }

    [TestCase("/")]
    [TestCase("/login.html")]
    [TestCase("/users/search?q=ali")]
    public async Task SV04_AllResponses_RefuseFraming(string path)
    {
        using var client = await _factory.LoginAsAsync("alice");

        var response = await client.GetAsync(path);

        Assert.That(response.Headers.GetValues("X-Frame-Options").Single(), Is.EqualTo("DENY"));
    }
}
