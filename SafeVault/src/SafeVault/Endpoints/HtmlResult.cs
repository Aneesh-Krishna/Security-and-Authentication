using SafeVault.Security;

namespace SafeVault.Endpoints;

internal static class HtmlResult
{
    public static IResult Page(string html, int statusCode = StatusCodes.Status200OK) =>
        Results.Content(html, "text/html; charset=utf-8", statusCode: statusCode);

    public static IResult Message(
        string title, IEnumerable<string> messages, int statusCode, string backLink = "/", string backText = "Back") =>
        Page(SafeHtml.Page(title, messages, backLink, backText), statusCode);

    public static IResult InvalidForm(string title, string backLink = "/") =>
        Message(title, ["The request must be a valid form submission."], StatusCodes.Status400BadRequest, backLink, "Back");

    public static IResult InvalidAntiforgeryToken(string backLink) =>
        Message("Request rejected", ["The form was missing a valid anti-forgery token. Reload the page and try again."],
            StatusCodes.Status400BadRequest, backLink, "Back");
}
