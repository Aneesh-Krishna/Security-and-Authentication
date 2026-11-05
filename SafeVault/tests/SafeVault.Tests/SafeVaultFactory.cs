using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SafeVault.Data;
using SafeVault.Security;

namespace SafeVault.Tests;

/// <summary>Runs the real app in memory with its own temporary SQLite database.</summary>
/// <param name="accountRequestsPerMinute">
/// Rate limit for /login and /submit. Set high by default so ordinary tests aren't throttled.
/// </param>
public sealed class SafeVaultFactory(int accountRequestsPerMinute = 1000) : WebApplicationFactory<Program>
{
    public const string Password = "Correct-Horse-Battery-9";

    private readonly string _databasePath = Path.Combine(Path.GetTempPath(), $"safevault-tests-{Guid.NewGuid()}.db");

    public UserRepository Users => Services.GetRequiredService<UserRepository>();

    protected override void ConfigureWebHost(IWebHostBuilder builder) =>
        builder.ConfigureAppConfiguration((_, config) => config.AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:SafeVault"] = $"Data Source={_databasePath}",
            ["Security:BcryptWorkFactor"] = "4", // the lowest bcrypt allows, to keep tests fast. Never use in production.
            ["Security:AccountRequestsPerMinute"] = accountRequestsPerMinute.ToString(),
        }));

    /// <summary>
    /// A client that behaves like a browser: HTTPS (the login cookie is Secure-only),
    /// keeps cookies between requests, and doesn't follow redirects so tests can check them.
    /// </summary>
    public HttpClient CreateBrowser(bool handleCookies = true) => CreateClient(new WebApplicationFactoryClientOptions
    {
        BaseAddress = new Uri("https://localhost"),
        AllowAutoRedirect = false,
        HandleCookies = handleCookies,
    });

    public User CreateUser(string username, string role = Roles.User)
    {
        var result = Services.GetRequiredService<AuthService>()
            .Register(username, $"{username}@example.com", Password, Password, role);
        return result.User ?? throw new InvalidOperationException(string.Join(" ", result.Errors));
    }

    public async Task<HttpClient> LoginAsAsync(string username, string role = Roles.User)
    {
        CreateUser(username, role);
        var client = CreateBrowser();
        var response = await client.LoginAsync(username, Password);
        Assert.That(response.StatusCode, Is.EqualTo(System.Net.HttpStatusCode.Redirect), $"Login as {username} failed.");
        return client;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            SqliteConnection.ClearAllPools();
            File.Delete(_databasePath);
        }
    }
}

public static partial class HttpClientExtensions
{
    public static Task<HttpResponseMessage> PostFormAsync(
        this HttpClient client, string path, IEnumerable<KeyValuePair<string, string>> fields) =>
        client.PostAsync(path, new FormUrlEncodedContent(fields));

    public static Task<HttpResponseMessage> RegisterAsync(
        this HttpClient client, string username, string email,
        string password = SafeVaultFactory.Password, string? confirmPassword = null,
        params KeyValuePair<string, string>[] extraFields) =>
        client.PostFormAsync("/submit", new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"] = email,
            ["password"] = password,
            ["confirmPassword"] = confirmPassword ?? password,
        }.Concat(extraFields));

    public static Task<HttpResponseMessage> LoginAsync(this HttpClient client, string username, string password) =>
        client.PostFormAsync("/login", new Dictionary<string, string> { ["username"] = username, ["password"] = password });

    /// <summary>Loads a page and reads the anti-forgery token out of its form, as a browser would submit it.</summary>
    public static async Task<string> GetAntiforgeryTokenAsync(this HttpClient client, string pagePath)
    {
        var html = await client.GetStringAsync(pagePath);
        return AntiforgeryTokenPattern().Match(html) is { Success: true } match
            ? match.Groups[1].Value
            : throw new InvalidOperationException($"No anti-forgery token found on {pagePath}.");
    }

    [GeneratedRegex("""name="__RequestVerificationToken" value="([^"]+)""")]
    private static partial Regex AntiforgeryTokenPattern();
}
