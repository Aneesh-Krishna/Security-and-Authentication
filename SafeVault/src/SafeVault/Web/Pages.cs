using Microsoft.AspNetCore.Antiforgery;
using SafeVault.Data;
using SafeVault.Security;
using static SafeVault.Security.SafeHtml;

namespace SafeVault.Web;

/// <summary>Server-rendered pages for signed-in users. All values are encoded by <see cref="SafeHtml.Html"/>.</summary>
public static class Pages
{
    public static string Dashboard(User user, AntiforgeryTokenSet tokens) => Page("Dashboard", Html($"""
        <p>Signed in as <strong>{user.Username}</strong> ({user.Email}).</p>
        <p>Role: {user.Role}</p>
        {(user.Role == Roles.Admin ? Html($"""<p><a href="/admin">Open the Admin Dashboard</a></p>""") : HtmlString.Empty)}
        <form method="post" action="/logout">
            {AntiforgeryField(tokens)}
            <button type="submit">Log out</button>
        </form>
        """));

    public static string AdminDashboard(IReadOnlyList<User> users, long currentUserId, AntiforgeryTokenSet tokens)
    {
        var rows = HtmlString.Join(users.Select(user => Html($"""
            <tr>
                <td>{user.UserId}</td>
                <td>{user.Username}</td>
                <td>{user.Email}</td>
                <td>{user.Role}</td>
                <td>{(user.UserId == currentUserId ? Html($"(you)") : RoleForm(user, tokens))}</td>
            </tr>
            """)));

        return Page("Admin Dashboard", Html($"""
            <p>{users.Count} registered users.</p>
            <table>
                <thead><tr><th>ID</th><th>Username</th><th>Email</th><th>Role</th><th>Change role</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
            <p><a href="/dashboard">Back to your dashboard</a></p>
            """));
    }

    private static HtmlString RoleForm(User user, AntiforgeryTokenSet tokens)
    {
        var newRole = user.Role == Roles.Admin ? Roles.User : Roles.Admin;
        return Html($"""
            <form method="post" action="/admin/users/{user.UserId}/role">
                {AntiforgeryField(tokens)}
                <input type="hidden" name="role" value="{newRole}">
                <button type="submit">Make {newRole}</button>
            </form>
            """);
    }

    private static HtmlString AntiforgeryField(AntiforgeryTokenSet tokens) =>
        Html($"""<input type="hidden" name="{tokens.FormFieldName}" value="{tokens.RequestToken}">""");
}
