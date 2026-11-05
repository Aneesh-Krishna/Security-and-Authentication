using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Encodings.Web;

namespace SafeVault.Security;

/// <summary>A piece of HTML that has already been built safely and must not be encoded again.</summary>
public readonly record struct HtmlString(string Value)
{
    public static readonly HtmlString Empty = new(string.Empty);

    public static HtmlString Join(IEnumerable<HtmlString> parts) => new(string.Concat(parts.Select(part => part.Value)));

    public override string ToString() => Value;
}

/// <summary>
/// Lets <c>SafeHtml.Html($"...")</c> HTML-encode every value placed in the template automatically.
/// Only other <see cref="HtmlString"/> values are inserted as-is, so forgetting to encode is impossible.
/// </summary>
[InterpolatedStringHandler]
public ref struct HtmlInterpolatedStringHandler(int literalLength, int formattedCount)
{
    private readonly StringBuilder _builder = new(literalLength + formattedCount * 16);

    public readonly void AppendLiteral(string value) => _builder.Append(value);

    public readonly void AppendFormatted(HtmlString value) => _builder.Append(value.Value);

    public readonly void AppendFormatted<T>(T value) =>
        _builder.Append(HtmlEncoder.Default.Encode(Convert.ToString(value, CultureInfo.InvariantCulture) ?? string.Empty));

    public readonly HtmlString ToHtml() => new(_builder.ToString());
}

/// <summary>
/// Builds HTML responses. Every piece of text is HTML-encoded before it is placed in the page,
/// so a value like "&lt;script&gt;" is displayed as text instead of being run by the browser.
/// </summary>
public static class SafeHtml
{
    public static HtmlString Html(HtmlInterpolatedStringHandler handler) => handler.ToHtml();

    public static string Page(string title, HtmlString body) => Html($"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{title}</title>
        </head>
        <body>
            <h1>{title}</h1>
            {body}
        </body>
        </html>
        """).Value;

    public static string Page(string title, IEnumerable<string> messages, string backLink = "/", string backText = "Back") =>
        Page(title, Html($"""
            <ul>{HtmlString.Join(messages.Select(message => Html($"<li>{message}</li>")))}</ul>
            <a href="{backLink}">{backText}</a>
            """));
}
