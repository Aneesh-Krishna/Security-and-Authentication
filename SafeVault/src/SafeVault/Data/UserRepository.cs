using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace SafeVault.Data;

public sealed record User(long UserId, string Username, string Email, string Role);

/// <summary>Login data. Kept separate from <see cref="User"/> so password hashes never reach pages or JSON.</summary>
public sealed record UserCredentials(
    long UserId, string PasswordHash, int FailedLoginAttempts, DateTimeOffset? LockoutEnd);

/// <summary>
/// A user plus their current security stamp: a random value copied into the login cookie.
/// Changing the stamp (on logout or role change) makes every existing cookie for that user invalid.
/// </summary>
public sealed record UserSession(User User, string SecurityStamp);

/// <summary>
/// Data access for the Users table. Every query uses parameters (@name placeholders),
/// so user input is always sent to the database as data and never becomes part of the SQL text.
/// Every SQL statement is a plain string literal: nothing is ever interpolated or concatenated into it.
/// </summary>
public sealed class UserRepository(string connectionString)
{
    public void EnsureSchema() => Execute("""
        CREATE TABLE IF NOT EXISTS Users (
            UserID              INTEGER PRIMARY KEY AUTOINCREMENT,
            Username            TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(Username) <= 100),
            Email               TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(Email) <= 100),
            PasswordHash        TEXT NOT NULL,
            Role                TEXT NOT NULL DEFAULT 'user' CHECK (Role IN ('user', 'admin')),
            FailedLoginAttempts INTEGER NOT NULL DEFAULT 0,
            LockoutEndUnixMs    INTEGER NULL,
            SecurityStamp       TEXT NOT NULL
        );
        """);

    public long AddUser(string username, string email, string passwordHash, string role = "user")
    {
        using var connection = Open();
        using var command = Command(connection, """
            INSERT INTO Users (Username, Email, PasswordHash, Role, SecurityStamp)
            VALUES (@username, @email, @hash, @role, @stamp)
            RETURNING UserID;
            """,
            Text("@username", username), Text("@email", email), Text("@hash", passwordHash), Text("@role", role),
            Text("@stamp", NewSecurityStamp()));
        return (long)command.ExecuteScalar()!;
    }

    public User? GetUserById(long userId) =>
        Query("SELECT UserID, Username, Email, Role FROM Users WHERE UserID = @id;",
            ReadUser, Integer("@id", userId)).SingleOrDefault();

    public User? GetUserByUsername(string username) =>
        Query("SELECT UserID, Username, Email, Role FROM Users WHERE Username = @username;",
            ReadUser, Text("@username", username)).SingleOrDefault();

    public User? GetUserByEmail(string email) =>
        Query("SELECT UserID, Username, Email, Role FROM Users WHERE Email = @email;",
            ReadUser, Text("@email", email)).SingleOrDefault();

    public IReadOnlyList<User> GetAllUsers() =>
        Query("SELECT UserID, Username, Email, Role FROM Users ORDER BY Username;", ReadUser);

    public UserSession? GetSession(long userId) =>
        Query("SELECT UserID, Username, Email, Role, SecurityStamp FROM Users WHERE UserID = @id;",
            reader => new UserSession(ReadUser(reader), reader.GetString(4)), Integer("@id", userId))
            .SingleOrDefault();

    /// <summary>Signs the user out everywhere: every cookie issued before this call stops working.</summary>
    public void RotateSecurityStamp(long userId) =>
        Execute("UPDATE Users SET SecurityStamp = @stamp WHERE UserID = @id;",
            Text("@stamp", NewSecurityStamp()), Integer("@id", userId));

    /// <summary>
    /// Finds users whose username contains <paramref name="term"/>. The term is passed as a
    /// parameter, and the LIKE wildcards % and _ inside it are escaped so they match literally.
    /// </summary>
    public IReadOnlyList<User> SearchByUsername(string term, int limit = 20) =>
        Query("""
            SELECT UserID, Username, Email, Role FROM Users
            WHERE Username LIKE @pattern ESCAPE '\'
            ORDER BY Username
            LIMIT @limit;
            """,
            ReadUser, Text("@pattern", "%" + EscapeLikePattern(term) + "%"), Integer("@limit", limit));

    public long CountUsers()
    {
        using var connection = Open();
        using var command = Command(connection, "SELECT COUNT(*) FROM Users;");
        return (long)command.ExecuteScalar()!;
    }

    public UserCredentials? GetCredentials(string username) =>
        Query("SELECT UserID, PasswordHash, FailedLoginAttempts, LockoutEndUnixMs FROM Users WHERE Username = @username;",
            reader => new UserCredentials(
                reader.GetInt64(0),
                reader.GetString(1),
                reader.GetInt32(2),
                reader.IsDBNull(3) ? null : DateTimeOffset.FromUnixTimeMilliseconds(reader.GetInt64(3))),
            Text("@username", username))
            .SingleOrDefault();

    /// <summary>
    /// Counts a failed login. On reaching <paramref name="maxAttempts"/> the account is locked
    /// until <paramref name="lockoutEnd"/> and the counter starts again. Done in one UPDATE so
    /// parallel login attempts can't race past the limit.
    /// </summary>
    public void RecordFailedLogin(long userId, int maxAttempts, DateTimeOffset lockoutEnd) => Execute("""
        UPDATE Users SET
            FailedLoginAttempts = CASE WHEN FailedLoginAttempts + 1 >= @max THEN 0 ELSE FailedLoginAttempts + 1 END,
            LockoutEndUnixMs    = CASE WHEN FailedLoginAttempts + 1 >= @max THEN @lockoutEnd ELSE LockoutEndUnixMs END
        WHERE UserID = @id;
        """,
        Integer("@max", maxAttempts), Integer("@lockoutEnd", lockoutEnd.ToUnixTimeMilliseconds()), Integer("@id", userId));

    public void ResetFailedLogins(long userId) =>
        Execute("UPDATE Users SET FailedLoginAttempts = 0, LockoutEndUnixMs = NULL WHERE UserID = @id;",
            Integer("@id", userId));

    public void UpdatePasswordHash(long userId, string passwordHash) =>
        Execute("UPDATE Users SET PasswordHash = @hash WHERE UserID = @id;",
            Text("@hash", passwordHash), Integer("@id", userId));

    /// <summary>Changes the role and signs the user out everywhere, so they log in again with the new role.</summary>
    public bool SetRole(long userId, string role) =>
        Execute("UPDATE Users SET Role = @role, SecurityStamp = @stamp WHERE UserID = @id;",
            Text("@role", role), Text("@stamp", NewSecurityStamp()), Integer("@id", userId)) == 1;

    private static User ReadUser(SqliteDataReader reader) =>
        new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3));

    private static string NewSecurityStamp() => Convert.ToHexString(RandomNumberGenerator.GetBytes(16));

    private static string EscapeLikePattern(string term) =>
        term.Replace(@"\", @"\\").Replace("%", @"\%").Replace("_", @"\_");

    private List<T> Query<T>(string sql, Func<SqliteDataReader, T> map, params SqliteParameter[] parameters)
    {
        using var connection = Open();
        using var command = Command(connection, sql, parameters);
        using var reader = command.ExecuteReader();

        var results = new List<T>();
        while (reader.Read())
            results.Add(map(reader));
        return results;
    }

    private int Execute(string sql, params SqliteParameter[] parameters)
    {
        using var connection = Open();
        using var command = Command(connection, sql, parameters);
        return command.ExecuteNonQuery();
    }

    private static SqliteCommand Command(SqliteConnection connection, string sql, params SqliteParameter[] parameters)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        command.Parameters.AddRange(parameters);
        return command;
    }

    private static SqliteParameter Text(string name, string value) => new(name, SqliteType.Text) { Value = value };

    private static SqliteParameter Integer(string name, long value) => new(name, SqliteType.Integer) { Value = value };

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }
}
