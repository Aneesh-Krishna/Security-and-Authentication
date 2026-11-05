using System.Text.Encodings.Web;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Data;
using SafeVault.Endpoints;
using SafeVault.Security;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddSingleton(services =>
{
    var connectionString = services.GetRequiredService<IConfiguration>().GetConnectionString("SafeVault")
        ?? throw new InvalidOperationException("Connection string 'SafeVault' is not configured.");
    return new UserRepository(connectionString);
});
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton(services => new PasswordHasher(
    services.GetRequiredService<IConfiguration>().GetValue("Security:BcryptWorkFactor", PasswordHasher.DefaultWorkFactor)));
builder.Services.AddSingleton<AuthService>();

// ASP.NET Core's default JSON settings leave "<", ">" and "&" unescaped. Use the strict encoder
// so JSON containing stored user content can never be read as HTML, even if it's put into a page.
builder.Services.ConfigureHttpJsonOptions(options =>
    options.SerializerOptions.Encoder = JavaScriptEncoder.Default);

// Authentication: who are you? A signed-in user carries an encrypted, tamper-proof cookie.
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "__Host-SafeVault";                // __Host- prefix: HTTPS only, this host only, path "/"
        options.Cookie.HttpOnly = true;                          // JavaScript can't read it, so XSS can't steal it
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // only ever sent over HTTPS
        options.Cookie.SameSite = SameSiteMode.Strict;           // not sent with requests from other sites (CSRF)
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
        options.LoginPath = "/login.html";
        options.Events.OnValidatePrincipal = UserPrincipal.ValidateAsync;
        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

// Authorization: what are you allowed to do?
builder.Services.AddAuthorizationBuilder()
    .AddPolicy(Policies.AdminOnly, policy => policy.RequireRole(Roles.Admin));

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "__Host-SafeVault-Antiforgery";
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.SuppressXFrameOptionsHeader = true; // the stricter X-Frame-Options: DENY below applies instead
});

// Limits login and registration attempts per client IP address. Behind a reverse proxy, add
// UseForwardedHeaders so the real client address is used instead of the proxy's.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.OnRejected = (context, _) =>
    {
        context.HttpContext.Response.Headers.RetryAfter = "60";
        return ValueTask.CompletedTask;
    };
    options.AddPolicy(Policies.AccountRateLimit, context =>
    {
        var permitsPerMinute = context.RequestServices.GetRequiredService<IConfiguration>()
            .GetValue("Security:AccountRequestsPerMinute", 10);
        return RateLimitPartition.GetFixedWindowLimiter(
            context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            _ => new FixedWindowRateLimiterOptions { PermitLimit = permitsPerMinute, Window = TimeSpan.FromMinutes(1) });
    });
});

var app = builder.Build();

app.Services.GetRequiredService<UserRepository>().EnsureSchema();
SeedAdmin(app);

if (!app.Environment.IsDevelopment())
    app.UseHsts();
app.UseHttpsRedirection();

// Defence in depth against XSS: even if unencoded output slipped through, the browser
// would refuse to run inline scripts or guess content types.
app.Use(async (context, next) =>
{
    var headers = context.Response.Headers;
    headers.ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";
    headers.XContentTypeOptions = "nosniff";
    headers.XFrameOptions = "DENY";       // clickjacking protection for browsers that ignore frame-ancestors
    headers.CacheControl = "no-store";    // pages and JSON may contain personal data; don't keep copies
    headers["Referrer-Policy"] = "no-referrer";
    await next();
});

app.UseCrossSiteRequestFilter();

app.UseDefaultFiles(new DefaultFilesOptions { DefaultFileNames = ["webform.html"] });
app.UseStaticFiles();

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapAccountEndpoints();
app.MapAdminEndpoints();

app.Run();

// Creates the first admin account from configuration, if one is configured and doesn't exist yet.
// Keep the password out of appsettings.json: use user-secrets or an environment variable.
static void SeedAdmin(WebApplication app)
{
    var seed = app.Configuration.GetSection("SeedAdmin");
    var username = seed["Username"];
    if (string.IsNullOrEmpty(username) || app.Services.GetRequiredService<UserRepository>().GetUserByUsername(username) is not null)
        return;

    var result = app.Services.GetRequiredService<AuthService>()
        .Register(username, seed["Email"], seed["Password"], seed["Password"], Roles.Admin);
    if (!result.Succeeded)
        throw new InvalidOperationException($"SeedAdmin settings are invalid: {string.Join(" ", result.Errors)}");
}

public partial class Program;
