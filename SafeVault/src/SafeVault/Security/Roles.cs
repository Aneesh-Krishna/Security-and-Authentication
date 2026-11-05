namespace SafeVault.Security;

public static class Roles
{
    public const string User = "user";
    public const string Admin = "admin";

    public static bool IsValid(string? role) => role is User or Admin;
}

public static class Policies
{
    public const string AdminOnly = "AdminOnly";
    public const string AccountRateLimit = "AccountRateLimit";
}
