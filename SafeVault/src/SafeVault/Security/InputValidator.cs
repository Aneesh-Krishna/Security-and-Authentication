using System.Text;
using System.Text.RegularExpressions;

namespace SafeVault.Security;

public sealed record ValidationResult(bool IsValid, string Value, string? Error)
{
    public static ValidationResult Valid(string value) => new(true, value, null);
    public static ValidationResult Invalid(string error) => new(false, string.Empty, error);
}

/// <summary>
/// Server-side input validation. Inputs are checked against an allow-list of known-good
/// characters and rejected if they don't match, rather than "cleaned" and accepted.
/// Browser-side checks (HTML5 attributes) are only for user experience and can be bypassed.
/// </summary>
public static partial class InputValidator
{
    public const int UsernameMinLength = 3;
    public const int UsernameMaxLength = 30;
    public const int EmailMaxLength = 100;
    public const int PasswordMinLength = 12;
    public const int PasswordMaxLength = 64;
    private const int PasswordMaxBytes = 72; // bcrypt ignores everything after the first 72 bytes

    // A real deployment would check against a large breached-password list
    // (e.g. the Have I Been Pwned range API); this short list shows the idea.
    private static readonly HashSet<string> CommonPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "password1234", "password12345", "passwordpassword", "123456789012", "1234567890123",
        "qwertyuiop12", "qwerty123456", "letmein12345", "iloveyou1234", "welcome12345",
        "administrator", "changeme1234", "safevault123", "safevault1234",
    };

    // \z (not $) so a trailing newline can't sneak past the end-of-string anchor.
    [GeneratedRegex(@"^[A-Za-z0-9_]{3,30}\z", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex UsernamePattern();

    [GeneratedRegex(@"^[A-Za-z0-9_%+-]+(\.[A-Za-z0-9_%+-]+)*@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\z",
        RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex EmailPattern();

    [GeneratedRegex(@"<[^>]*>", RegexOptions.None, matchTimeoutMilliseconds: 100)]
    private static partial Regex HtmlTagPattern();

    public static ValidationResult ValidateUsername(string? input)
    {
        var value = Normalize(input);

        if (value.Length == 0)
            return ValidationResult.Invalid("Username is required.");

        if (value.Length < UsernameMinLength || value.Length > UsernameMaxLength)
            return ValidationResult.Invalid(
                $"Username must be between {UsernameMinLength} and {UsernameMaxLength} characters.");

        if (!UsernamePattern().IsMatch(value))
            return ValidationResult.Invalid("Username may only contain letters, numbers and underscores.");

        return ValidationResult.Valid(value);
    }

    public static ValidationResult ValidateEmail(string? input)
    {
        var value = Normalize(input);

        if (value.Length == 0)
            return ValidationResult.Invalid("Email is required.");

        if (value.Length > EmailMaxLength)
            return ValidationResult.Invalid($"Email must be at most {EmailMaxLength} characters.");

        if (!EmailPattern().IsMatch(value))
            return ValidationResult.Invalid("Email address is not valid.");

        return ValidationResult.Valid(value.ToLowerInvariant());
    }

    /// <summary>
    /// Password rules follow NIST SP 800-63B: a minimum length and a check against common
    /// passwords, rather than composition rules ("one uppercase, one symbol...") that push
    /// people towards predictable patterns.
    /// </summary>
    public static ValidationResult ValidatePassword(string? input, string? username = null)
    {
        var value = (input ?? string.Empty).Normalize(NormalizationForm.FormKC);

        if (value.Length == 0)
            return ValidationResult.Invalid("Password is required.");

        if (value.Length < PasswordMinLength)
            return ValidationResult.Invalid($"Password must be at least {PasswordMinLength} characters.");

        if (value.Length > PasswordMaxLength || Encoding.UTF8.GetByteCount(value) > PasswordMaxBytes)
            return ValidationResult.Invalid("Password is too long.");

        if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl))
            return ValidationResult.Invalid("Password contains invalid characters.");

        if (CommonPasswords.Contains(value))
            return ValidationResult.Invalid("This password is too common. Choose a less predictable one.");

        if (!string.IsNullOrEmpty(username) && value.Contains(username, StringComparison.OrdinalIgnoreCase))
            return ValidationResult.Invalid("Password must not contain your username.");

        return ValidationResult.Valid(value);
    }

    /// <summary>
    /// Removes characters that are dangerous in HTML or script contexts from free-text input
    /// (HTML tags, quotes, angle brackets, backticks and control characters).
    /// Use this as an extra layer for free-text fields; it does not replace allow-list
    /// validation, parameterized queries or HTML-encoding on output.
    /// </summary>
    public static string SanitizeInput(string? input)
    {
        var value = Normalize(input);

        value = HtmlTagPattern().Replace(value, string.Empty);

        var builder = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            if (char.IsControl(c) || c is '<' or '>' or '"' or '\'' or '`')
                continue;
            builder.Append(c);
        }

        return builder.ToString().Trim();
    }

    // NFKC turns look-alike characters (e.g. full-width "＜") into their plain form ("<"),
    // so they are caught by the checks above instead of slipping past them.
    private static string Normalize(string? input) =>
        (input ?? string.Empty).Normalize(NormalizationForm.FormKC).Trim();
}
