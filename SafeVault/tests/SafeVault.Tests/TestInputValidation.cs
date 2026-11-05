// Tests/TestInputValidation.cs
using SafeVault.Security;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    internal static readonly string[] SqlInjectionPayloads =
    [
        "' OR '1'='1",
        "' OR 1=1 --",
        "admin'--",
        "admin' #",
        "admin' /*",
        "'; DROP TABLE Users; --",
        "1; DELETE FROM Users",
        "\" OR \"\"=\"",
        "' UNION SELECT UserID, Username, Email FROM Users --",
    ];

    internal static readonly string[] XssPayloads =
    [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "\"><script>alert(1)</script>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<scr<script>ipt>alert(1)</script>",
        "＜script＞alert(1)＜/script＞", // full-width brackets
        "javascript:alert(document.cookie)",
    ];

    [Test]
    public void TestForSQLInjection()
    {
        Assert.Multiple(() =>
        {
            foreach (var payload in SqlInjectionPayloads)
            {
                Assert.That(InputValidator.ValidateUsername(payload).IsValid, Is.False,
                    $"Username should reject: {payload}");
                Assert.That(InputValidator.ValidateEmail(payload).IsValid, Is.False,
                    $"Email should reject: {payload}");
                Assert.That(InputValidator.ValidateEmail($"{payload}@example.com").IsValid, Is.False,
                    $"Email should reject: {payload}@example.com");
            }
        });
    }

    [Test]
    public void TestForXSS()
    {
        Assert.Multiple(() =>
        {
            foreach (var payload in XssPayloads)
            {
                Assert.That(InputValidator.ValidateUsername(payload).IsValid, Is.False,
                    $"Username should reject: {payload}");
                Assert.That(InputValidator.ValidateEmail(payload).IsValid, Is.False,
                    $"Email should reject: {payload}");

                var sanitized = InputValidator.SanitizeInput(payload);
                Assert.That(sanitized, Does.Not.Contain("<").And.Not.Contain(">")
                    .And.Not.Contain("\"").And.Not.Contain("'").And.Not.Contain("`"),
                    $"Sanitized output still has dangerous characters: {sanitized}");
            }
        });
    }

    [TestCase("alice")]
    [TestCase("Bob_42")]
    [TestCase("abc")]
    [TestCase("a23456789012345678901234567890")] // exactly 30 characters
    public void ValidUsernames_AreAccepted(string username)
    {
        var result = InputValidator.ValidateUsername(username);

        Assert.That(result.IsValid, Is.True, result.Error);
        Assert.That(result.Value, Is.EqualTo(username));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("   ")]
    [TestCase("ab")]                               // too short
    [TestCase("a234567890123456789012345678901")]  // 31 characters, too long
    [TestCase("john doe")]                         // space
    [TestCase("john.doe")]                         // punctuation
    [TestCase("admin\n<script>")]                  // embedded newline
    [TestCase("admin\0")]                          // null byte
    public void InvalidUsernames_AreRejected(string? username)
    {
        var result = InputValidator.ValidateUsername(username);

        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Error, Is.Not.Empty);
    }

    [Test]
    public void Username_IsTrimmed()
    {
        Assert.That(InputValidator.ValidateUsername("  alice  ").Value, Is.EqualTo("alice"));
    }

    [TestCase("alice@example.com", "alice@example.com")]
    [TestCase("First.Last+tag@Sub.Example.co.uk", "first.last+tag@sub.example.co.uk")]
    public void ValidEmails_AreAcceptedAndLowercased(string email, string expected)
    {
        var result = InputValidator.ValidateEmail(email);

        Assert.That(result.IsValid, Is.True, result.Error);
        Assert.That(result.Value, Is.EqualTo(expected));
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("plainaddress")]
    [TestCase("alice@")]
    [TestCase("alice@example")]
    [TestCase("alice@@example.com")]
    [TestCase(".alice@example.com")]
    [TestCase("alice..bob@example.com")]
    [TestCase("alice@example.com<script>")]
    [TestCase("alice@example.com\nBcc: victim@example.com")] // header injection
    public void InvalidEmails_AreRejected(string? email)
    {
        Assert.That(InputValidator.ValidateEmail(email).IsValid, Is.False);
    }

    [Test]
    public void Email_LongerThanColumn_IsRejected()
    {
        var email = new string('a', 90) + "@example.com"; // 102 characters

        Assert.That(InputValidator.ValidateEmail(email).IsValid, Is.False);
    }

    [TestCase("Correct-Horse-Battery-9")]
    [TestCase("four random words here")]
    [TestCase("exactly12chr")]
    public void StrongPasswords_AreAccepted(string password)
    {
        Assert.That(InputValidator.ValidatePassword(password).IsValid, Is.True);
    }

    [TestCase(null)]
    [TestCase("")]
    [TestCase("elevenchars")]                 // 11 characters
    [TestCase("            ")]                // only spaces
    [TestCase("Password1234")]                // common (checked case-insensitively)
    [TestCase("tab\tinside password")]        // control character
    public void WeakPasswords_AreRejected(string? password)
    {
        Assert.That(InputValidator.ValidatePassword(password).IsValid, Is.False);
    }

    [Test]
    public void Password_LongerThan64Characters_IsRejected()
    {
        Assert.That(InputValidator.ValidatePassword(new string('x', 65)).IsValid, Is.False);
    }

    [Test]
    public void Password_Over72Bytes_IsRejected_BecauseBcryptWouldIgnoreTheRest()
    {
        var password = new string('é', 40); // 40 characters, but 80 bytes in UTF-8

        Assert.That(InputValidator.ValidatePassword(password).IsValid, Is.False);
    }

    [TestCase("<b>Hello</b> world", "Hello world")]
    [TestCase("<script>alert(1)</script>", "alert(1)")]
    [TestCase("Tab\there\u0007", "Tabhere")]
    [TestCase("O'Brien said \"hi\"", "OBrien said hi")]
    [TestCase(null, "")]
    public void SanitizeInput_RemovesDangerousContent(string? input, string expected)
    {
        Assert.That(InputValidator.SanitizeInput(input), Is.EqualTo(expected));
    }

    [Test]
    public void SafeHtml_EncodesScriptsInOutput()
    {
        var html = SafeHtml.Page("Result", ["<script>alert('xss')</script>", "<img src=x onerror=alert(1)>"]);

        Assert.Multiple(() =>
        {
            Assert.That(html, Does.Not.Contain("<script>"));
            Assert.That(html, Does.Not.Contain("<img"));
            Assert.That(html, Does.Contain("&lt;script&gt;"));
        });
    }
}
