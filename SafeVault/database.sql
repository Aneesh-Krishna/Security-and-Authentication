-- database.sql
-- Reference schema (MySQL syntax). The app itself runs on SQLite and creates an
-- equivalent table on startup in src/SafeVault/Data/UserRepository.cs.

CREATE TABLE Users (
    UserID              INT PRIMARY KEY AUTO_INCREMENT,
    Username            VARCHAR(100) NOT NULL UNIQUE,
    Email               VARCHAR(100) NOT NULL UNIQUE,
    PasswordHash        CHAR(60)     NOT NULL,                -- bcrypt hash (includes its own salt), never the password
    Role                VARCHAR(10)  NOT NULL DEFAULT 'user' CHECK (Role IN ('user', 'admin')),
    FailedLoginAttempts INT          NOT NULL DEFAULT 0,      -- brute-force protection
    LockoutEndUnixMs    BIGINT       NULL,                    -- account locked until this time
    SecurityStamp       CHAR(32)     NOT NULL                 -- changed on logout/role change to end all sessions
);

-- Least privilege: the application's database account can read, insert and update users,
-- but can't DELETE rows or DROP/ALTER tables, even if an injection flaw existed.
CREATE USER 'safevault_app'@'localhost' IDENTIFIED BY 'change-me';
GRANT SELECT, INSERT, UPDATE ON Users TO 'safevault_app'@'localhost';

-- Parameterized queries used by the application. The placeholders (@username, @email, ...)
-- are filled in by the database driver as data, never by string concatenation.
--
--   INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@username, @email, @hash, @role);
--   SELECT UserID, Username, Email, Role FROM Users WHERE Username = @username;
--   SELECT UserID, PasswordHash, FailedLoginAttempts, LockoutEndUnixMs FROM Users WHERE Username = @username;
--   UPDATE Users SET Role = @role, SecurityStamp = @stamp WHERE UserID = @id;
--   UPDATE Users SET SecurityStamp = @stamp WHERE UserID = @id;
--   SELECT UserID, Username, Email, Role FROM Users WHERE Username LIKE @pattern ESCAPE '\\' LIMIT 20;
