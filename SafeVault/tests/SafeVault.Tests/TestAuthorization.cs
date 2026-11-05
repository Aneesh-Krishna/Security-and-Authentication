using System.Net;
using SafeVault.Security;

namespace SafeVault.Tests;

/// <summary>
/// Access-control tests over real HTTP: anonymous visitors, normal users and admins
/// each try the protected routes, the way a browser or an attacker would.
/// </summary>
[TestFixture]
public class TestAuthorization
{
    private SafeVaultFactory _factory = null!;

    [SetUp]
    public void SetUp() => _factory = new SafeVaultFactory();

    [TearDown]
    public void TearDown() => _factory.Dispose();

    private static Task<HttpResponseMessage> PostRoleChange(HttpClient client, long userId, string role, string? token) =>
        client.PostFormAsync($"/admin/users/{userId}/role", new Dictionary<string, string>
        {
            ["role"] = role,
            ["__RequestVerificationToken"] = token ?? string.Empty,
        });

    // ---- Login over HTTP ----

    [Test]
    public async Task Login_Success_IssuesHardenedCookie_AndRedirectsToDashboard()
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser();

        var response = await client.LoginAsync("alice", SafeVaultFactory.Password);
        var cookie = response.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-SafeVault="));

        Assert.Multiple(() =>
        {
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.OriginalString, Is.EqualTo("/dashboard"));
            Assert.That(cookie, Does.Contain("secure").IgnoreCase);
            Assert.That(cookie, Does.Contain("httponly").IgnoreCase);
            Assert.That(cookie, Does.Contain("samesite=strict").IgnoreCase);
        });
    }

    [Test]
    public async Task Login_Failure_GivesSameResponse_ForWrongPasswordAndUnknownUser()
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser();

        var wrongPassword = await client.LoginAsync("alice", "wrong-password-123");
        var unknownUser = await client.LoginAsync("nobody", "wrong-password-123");

        Assert.Multiple(async () =>
        {
            Assert.That(wrongPassword.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(unknownUser.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(await wrongPassword.Content.ReadAsStringAsync(),
                Is.EqualTo(await unknownUser.Content.ReadAsStringAsync()),
                "Different messages would reveal which usernames exist.");
            Assert.That(wrongPassword.Headers.Contains("Set-Cookie") &&
                wrongPassword.Headers.GetValues("Set-Cookie").Any(c => c.StartsWith("__Host-SafeVault=")), Is.False);
        });
    }

    [Test]
    public async Task Login_LockedAccount_IsRefusedOverHttp()
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser();

        for (var attempt = 0; attempt < AuthService.MaxFailedAttempts; attempt++)
            await client.LoginAsync("alice", "wrong-password-123");

        var response = await client.LoginAsync("alice", SafeVaultFactory.Password);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task TamperedCookie_IsRejected()
    {
        _factory.CreateUser("alice");
        using var client = _factory.CreateBrowser(handleCookies: false);
        var login = await client.LoginAsync("alice", SafeVaultFactory.Password);
        var cookie = login.Headers.GetValues("Set-Cookie").Single(c => c.StartsWith("__Host-SafeVault=")).Split(';')[0];
        var value = cookie["__Host-SafeVault=".Length..];
        var tampered = $"__Host-SafeVault={value[..^5]}{(value[^5] == 'A' ? 'B' : 'A')}{value[^4..]}";

        async Task<HttpResponseMessage> GetDashboardWith(string cookieHeader)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, "/dashboard");
            request.Headers.Add("Cookie", cookieHeader);
            return await client.SendAsync(request);
        }

        Assert.That((await GetDashboardWith(cookie)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That((await GetDashboardWith(tampered)).StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    // ---- Anonymous visitors ----

    [TestCase("/dashboard")]
    [TestCase("/admin")]
    [TestCase("/users/search?q=a")]
    public async Task Anonymous_IsRedirectedToLogin(string path)
    {
        using var client = _factory.CreateBrowser();

        var response = await client.GetAsync(path);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.AbsolutePath, Is.EqualTo("/login.html"));
    }

    [Test]
    public async Task Anonymous_CannotChangeRoles()
    {
        var victim = _factory.CreateUser("victim");
        using var client = _factory.CreateBrowser();

        var response = await PostRoleChange(client, victim.UserId, Roles.Admin, token: null);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(_factory.Users.GetUserById(victim.UserId)!.Role, Is.EqualTo(Roles.User));
    }

    [TestCase("/")]
    [TestCase("/login.html")]
    public async Task Anonymous_CanSeePublicPages(string path)
    {
        using var client = _factory.CreateBrowser();

        Assert.That((await client.GetAsync(path)).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    // ---- Normal users ----

    [Test]
    public async Task User_CanSeeOwnDashboard_WithoutAdminLink()
    {
        using var client = await _factory.LoginAsAsync("alice");

        var body = await client.GetStringAsync("/dashboard");

        Assert.That(body, Does.Contain("alice"));
        Assert.That(body, Does.Contain("Role: user"));
        Assert.That(body, Does.Not.Contain("/admin"));
    }

    [Test]
    public async Task User_IsForbiddenFromAdminDashboard()
    {
        using var client = await _factory.LoginAsAsync("alice");

        var response = await client.GetAsync("/admin");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task User_CannotPromoteThemselves_EvenWithValidAntiforgeryToken()
    {
        using var client = await _factory.LoginAsAsync("alice");
        var alice = _factory.Users.GetUserByUsername("alice")!;
        var token = await client.GetAntiforgeryTokenAsync("/dashboard");

        var response = await PostRoleChange(client, alice.UserId, Roles.Admin, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That(_factory.Users.GetUserById(alice.UserId)!.Role, Is.EqualTo(Roles.User));
    }

    [Test]
    public async Task Registration_IgnoresRoleFieldInForm()
    {
        using var client = _factory.CreateBrowser();

        await client.RegisterAsync("sneaky", "sneaky@example.com",
            extraFields: [new("role", Roles.Admin), new("Role", Roles.Admin)]);

        Assert.That(_factory.Users.GetUserByUsername("sneaky")!.Role, Is.EqualTo(Roles.User));
    }

    // ---- Admins ----

    [Test]
    public async Task Admin_CanSeeAdminDashboard_WithAllUsers()
    {
        _factory.CreateUser("alice");
        using var client = await _factory.LoginAsAsync("root", Roles.Admin);

        var response = await client.GetAsync("/admin");
        var body = await response.Content.ReadAsStringAsync();

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(body, Does.Contain("alice@example.com").And.Contain("root@example.com"));
    }

    [Test]
    public async Task Admin_CanPromoteUser_WhoThenGainsAccess()
    {
        var alice = _factory.CreateUser("alice");
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);
        var token = await admin.GetAntiforgeryTokenAsync("/admin");

        var response = await PostRoleChange(admin, alice.UserId, Roles.Admin, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(_factory.Users.GetUserById(alice.UserId)!.Role, Is.EqualTo(Roles.Admin));

        using var aliceClient = _factory.CreateBrowser();
        await aliceClient.LoginAsync("alice", SafeVaultFactory.Password);
        Assert.That((await aliceClient.GetAsync("/admin")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task DemotedAdmin_LosesAccessImmediately()
    {
        using var root = await _factory.LoginAsAsync("root", Roles.Admin);
        using var bob = await _factory.LoginAsAsync("bob", Roles.Admin);
        Assert.That((await bob.GetAsync("/admin")).StatusCode, Is.EqualTo(HttpStatusCode.OK));

        var token = await root.GetAntiforgeryTokenAsync("/admin");
        await PostRoleChange(root, _factory.Users.GetUserByUsername("bob")!.UserId, Roles.User, token);

        // Bob's cookie still says "admin", but the server re-checks the database on each request.
        Assert.That((await bob.GetAsync("/admin")).StatusCode, Is.Not.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_RoleChange_WithoutAntiforgeryToken_IsRejected()
    {
        var alice = _factory.CreateUser("alice");
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);

        var missing = await PostRoleChange(admin, alice.UserId, Roles.Admin, token: null);
        var forged = await PostRoleChange(admin, alice.UserId, Roles.Admin, token: "forged-token");

        Assert.That(missing.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(forged.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(_factory.Users.GetUserById(alice.UserId)!.Role, Is.EqualTo(Roles.User));
    }

    [Test]
    public async Task Admin_CannotUseAnotherUsersAntiforgeryToken()
    {
        var alice = _factory.CreateUser("alice");
        using var mallory = await _factory.LoginAsAsync("mallory");
        var mallorysToken = await mallory.GetAntiforgeryTokenAsync("/dashboard");
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);

        var response = await PostRoleChange(admin, alice.UserId, Roles.Admin, mallorysToken);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [TestCase("superadmin")]
    [TestCase("")]
    [TestCase("ADMIN")]
    public async Task Admin_CannotAssignUnknownRole(string role)
    {
        var alice = _factory.CreateUser("alice");
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);
        var token = await admin.GetAntiforgeryTokenAsync("/admin");

        var response = await PostRoleChange(admin, alice.UserId, role, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(_factory.Users.GetUserById(alice.UserId)!.Role, Is.EqualTo(Roles.User));
    }

    [Test]
    public async Task Admin_CannotDemoteThemselves()
    {
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);
        var root = _factory.Users.GetUserByUsername("root")!;
        // The admin page shows no role form for your own row, so take a valid token from the dashboard.
        var token = await admin.GetAntiforgeryTokenAsync("/dashboard");

        var response = await PostRoleChange(admin, root.UserId, Roles.User, token);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(_factory.Users.GetUserById(root.UserId)!.Role, Is.EqualTo(Roles.Admin));
    }

    [Test]
    public async Task AdminDashboard_EncodesStoredXss()
    {
        // Written straight to the database, bypassing validation, as if it came from an older
        // version of the app or another system. The page must still display it as text.
        _factory.Users.AddUser("<script>alert(1)</script>", "evil@example.com", "not-a-real-hash");
        using var admin = await _factory.LoginAsAsync("root", Roles.Admin);

        var body = await admin.GetStringAsync("/admin");

        Assert.That(body, Does.Not.Contain("<script>alert(1)</script>"));
        Assert.That(body, Does.Contain("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    // ---- Logout ----

    [Test]
    public async Task Logout_EndsSession()
    {
        using var client = await _factory.LoginAsAsync("alice");
        var token = await client.GetAntiforgeryTokenAsync("/dashboard");

        var logout = await client.PostFormAsync("/logout",
            new Dictionary<string, string> { ["__RequestVerificationToken"] = token });

        Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That((await client.GetAsync("/dashboard")).StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task Logout_WithoutAntiforgeryToken_IsRejected()
    {
        using var client = await _factory.LoginAsAsync("alice");

        var logout = await client.PostFormAsync("/logout", []);

        Assert.That(logout.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That((await client.GetAsync("/dashboard")).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
}
