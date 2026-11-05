using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SafeVault.Data;
using SafeVault.Security;
using SafeVault.Web;

namespace SafeVault.Endpoints;

public static class AccountEndpoints
{
    // One message for unknown usernames, wrong passwords and locked accounts, so an attacker
    // can't use the login form to find out which usernames exist.
    private const string LoginFailedMessage =
        "Invalid username or password. After 5 failed attempts the account is locked for 15 minutes.";

    public static void MapAccountEndpoints(this WebApplication app)
    {
        // Rate-limited per client IP, so one client can't guess passwords quickly,
        // lock many accounts in a row, or mass-register accounts.
        app.MapPost("/submit", Register).RequireRateLimiting(Policies.AccountRateLimit);
        app.MapPost("/login", Login).RequireRateLimiting(Policies.AccountRateLimit);
        app.MapPost("/logout", Logout).RequireAuthorization();
        app.MapGet("/dashboard", Dashboard).RequireAuthorization();
        app.MapGet("/users/search", Search).RequireAuthorization();
    }

    private static async Task<IResult> Register(HttpRequest request, AuthService auth)
    {
        if (await FormReader.TryReadFormAsync(request) is not { } form)
            return HtmlResult.InvalidForm("Registration failed");

        // Only these fields are read. Any "role" field an attacker adds is ignored:
        // new accounts always get the "user" role.
        var result = auth.Register(form["username"], form["email"], form["password"], form["confirmPassword"]);

        if (!result.Succeeded)
            return HtmlResult.Message("Registration failed", result.Errors,
                result.IsDuplicate ? StatusCodes.Status409Conflict : StatusCodes.Status400BadRequest);

        return HtmlResult.Message("Registration successful", [$"Welcome, {result.User!.Username}! You can now log in."],
            StatusCodes.Status200OK, "/login.html", "Log in");
    }

    private static async Task<IResult> Login(HttpContext context, AuthService auth)
    {
        if (await FormReader.TryReadFormAsync(context.Request) is not { } form)
            return HtmlResult.InvalidForm("Login failed", "/login.html");

        var result = auth.Login(form["username"], form["password"]);

        if (result.Status != LoginStatus.Success)
            return HtmlResult.Message("Login failed", [LoginFailedMessage], StatusCodes.Status401Unauthorized,
                "/login.html", "Try again");

        // Signing in issues a brand-new cookie, so a session ID planted before login is never reused.
        await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, UserPrincipal.Create(result.Session!));

        // Always a fixed local path. Redirecting to a URL taken from the request would be an open redirect.
        return Results.LocalRedirect("/dashboard");
    }

    private static async Task<IResult> Logout(HttpContext context, IAntiforgery antiforgery, UserRepository users)
    {
        if (await FormReader.TryReadFormAsync(context.Request) is null)
            return HtmlResult.InvalidForm("Logout failed", "/dashboard");
        if (!await antiforgery.IsRequestValidAsync(context))
            return HtmlResult.InvalidAntiforgeryToken("/dashboard");

        // Deleting the browser's cookie isn't enough: a copy stolen earlier would still work.
        // Changing the security stamp makes every cookie issued for this user invalid.
        users.RotateSecurityStamp(UserPrincipal.GetUserId(context.User));
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Results.LocalRedirect("/login.html");
    }

    private static IResult Dashboard(HttpContext context, UserRepository users, IAntiforgery antiforgery)
    {
        var user = users.GetUserById(UserPrincipal.GetUserId(context.User));
        if (user is null)
            return Results.Challenge();

        return HtmlResult.Page(Pages.Dashboard(user, antiforgery.GetAndStoreTokens(context)));
    }

    private static IResult Search(string? q, UserRepository users)
    {
        var term = q?.Trim() ?? string.Empty;
        if (term.Length is 0 or > InputValidator.UsernameMaxLength)
            return Results.BadRequest(new { error = $"Search term must be 1-{InputValidator.UsernameMaxLength} characters." });

        // Only public fields are returned; email addresses and roles stay private.
        var matches = users.SearchByUsername(term).Select(user => new { user.UserId, user.Username });
        return Results.Ok(matches);
    }
}
