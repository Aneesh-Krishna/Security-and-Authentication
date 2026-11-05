using Microsoft.AspNetCore.Antiforgery;
using SafeVault.Data;
using SafeVault.Security;
using SafeVault.Web;

namespace SafeVault.Endpoints;

public static class AdminEndpoints
{
    public static void MapAdminEndpoints(this WebApplication app)
    {
        // The policy is applied to the whole group, so a new admin route can't be added
        // without protection by mistake.
        var admin = app.MapGroup("/admin").RequireAuthorization(Policies.AdminOnly);

        admin.MapGet("", Dashboard);
        admin.MapPost("/users/{id:long}/role", ChangeRole);
    }

    private static IResult Dashboard(HttpContext context, UserRepository users, IAntiforgery antiforgery) =>
        HtmlResult.Page(Pages.AdminDashboard(
            users.GetAllUsers(), UserPrincipal.GetUserId(context.User), antiforgery.GetAndStoreTokens(context)));

    private static async Task<IResult> ChangeRole(long id, HttpContext context, AuthService auth, IAntiforgery antiforgery)
    {
        if (await FormReader.TryReadFormAsync(context.Request) is not { } form)
            return HtmlResult.InvalidForm("Role change failed", "/admin");
        if (!await antiforgery.IsRequestValidAsync(context))
            return HtmlResult.InvalidAntiforgeryToken("/admin");

        var error = auth.ChangeRole(UserPrincipal.GetUserId(context.User), id, form["role"]);

        if (error is not null)
            return HtmlResult.Message("Role change failed", [error], StatusCodes.Status400BadRequest, "/admin", "Back");

        return Results.LocalRedirect("/admin");
    }
}
