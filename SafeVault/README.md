# SafeVault

SafeVault is an ASP.NET Core (.NET 10) web app with an NUnit test suite, secured step by step across three activities:

| Activity | Topic | Status |
|---|---|---|
| 1 | Secure coding: input validation, SQL injection and XSS | Done |
| 2 | Authentication and role-based authorization | Done |
| 3 | Debugging and fixing vulnerabilities | Done. See [SECURITY-SUMMARY.md](SECURITY-SUMMARY.md) |

## Project layout

```
SafeVault/
├── SECURITY-SUMMARY.md                 Activity 3: vulnerabilities found, fixes applied, test evidence
├── database.sql                        Reference schema (MySQL) and the parameterized queries used
├── src/SafeVault/
│   ├── Program.cs                      Cookie auth, authorization, rate limiting, JSON encoding, security headers
│   ├── Endpoints/AccountEndpoints.cs   /submit (register), /login, /logout, /dashboard, /users/search
│   ├── Endpoints/AdminEndpoints.cs     /admin and /admin/users/{id}/role, admin role only
│   ├── Endpoints/FormReader.cs         Reads form posts; malformed forms get 400 instead of crashing
│   ├── Security/AuthService.cs         Registration, login, lockout, role changes
│   ├── Security/CrossSiteRequestFilter.cs  Blocks cross-site POSTs (CSRF), including on login/registration
│   ├── Security/PasswordHasher.cs      bcrypt hashing
│   ├── Security/Roles.cs               Roles, the AdminOnly policy and the rate-limit policy name
│   ├── Security/UserPrincipal.cs       Login-cookie claims; re-checks role and security stamp on every request
│   ├── Security/InputValidator.cs      Allow-list validation, password rules, sanitizer
│   ├── Security/SafeHtml.cs            HTML templates that encode every value automatically
│   ├── Web/Pages.cs                    Dashboard and Admin Dashboard pages
│   ├── Data/UserRepository.cs          SQLite data access using parameterized queries only
│   └── wwwroot/                        webform.html (register), login.html, js/register.js
└── tests/SafeVault.Tests/
    ├── TestInputValidation.cs          Activity 1: TestForSQLInjection / TestForXSS, plus password rules
    ├── TestUserRepository.cs           Activity 1: injection payloads run directly against the database
    ├── TestSubmitEndpoint.cs           Activity 1: attack simulations over HTTP
    ├── TestAuthentication.cs           Activity 2: hashing, login, lockout, registration, role assignment
    ├── TestAuthorization.cs            Activity 2: access control for anonymous visitors, users and admins
    ├── TestSecurityFixes.cs            Activity 3: regression tests for each vulnerability fixed
    ├── TestAttackScenarios.cs          Activity 3: every payload in every form field, second-order injection
    └── SafeVaultFactory.cs             Test host: runs the app in memory with a temporary database
```

---

## Activity 1: Secure coding

### Input validation (Step 2)

- **Allow-list validation.** A username is 3-30 characters of `[A-Za-z0-9_]`. An email must match a strict pattern and be at most 100 characters. Anything else is rejected, not silently "fixed".
- **Unicode normalization.** Input is normalized (NFKC) before it is checked, so look-alike characters such as a full-width `＜` can't get past the checks.
- **Safe regexes.** The patterns use `\z` rather than `$` and have a 100 ms timeout.
- **`SanitizeInput`.** Strips HTML tags, quotes, backticks and control characters from free text, as an extra layer.
- **HTML5 attributes in the form.** These are for the user's convenience only. The server checks everything again.

### Parameterized queries (Step 3)

- Every query uses `@placeholders` with typed parameters. User input is never concatenated into SQL text.
- `LIKE` searches escape `%` and `_`, so they match those characters literally.

### XSS protection on output

- Pages are built with `SafeHtml.Html($"...")`. This HTML-encodes every value placed in a template unless the value is itself safe HTML, so forgetting to encode isn't possible.
- Every response carries a `Content-Security-Policy` header (no inline scripts) and `X-Content-Type-Options: nosniff`.

---

## Activity 2: Authentication and authorization

### Authentication (Step 2)

| Feature | How it works |
|---|---|
| **Password hashing** | bcrypt with work factor 12 (`BCrypt.Net-Next`). Each hash has its own random salt, so the same password produces a different hash for each user. Plain-text passwords are never stored. |
| **Password rules** | Follow NIST SP 800-63B: 12-64 characters, not on a common-password list, and must not contain the username. There are no "must include a symbol" rules. Passwords over 72 bytes are rejected, because bcrypt ignores everything after 72 bytes. |
| **Login check** | `AuthService.Login` looks up the user and checks the password with `BCrypt.Verify`. |
| **No username enumeration** | Unknown usernames, wrong passwords and locked accounts all get the same message. Unknown usernames still run a full bcrypt check, so the response time doesn't reveal whether an account exists. |
| **Brute-force lockout** | 5 failed attempts lock the account for 15 minutes. The counter is updated in a single SQL statement, so parallel attempts can't get past the limit. |
| **Hash upgrades** | If the work factor is raised later, a user's hash is upgraded the next time they log in. |
| **Session cookie** | Named `__Host-SafeVault`. It is `HttpOnly` (JavaScript can't read it), `Secure` (HTTPS only), `SameSite=Strict` (not sent from other sites), and encrypted and signed by ASP.NET Core. It expires after 30 minutes of inactivity. |
| **No open redirect** | After login, the user always goes to `/dashboard`, never to a URL taken from the request. |

### Role-based authorization (Step 3)

| Route | Anonymous | `user` | `admin` |
|---|---|---|---|
| `/`, `/login.html`, `POST /submit`, `POST /login` | ✓ | ✓ | ✓ |
| `/dashboard`, `POST /logout`, `/users/search` | Redirected to login | ✓ | ✓ |
| `/admin` (Admin Dashboard) | Redirected to login | **403 Forbidden** | ✓ |
| `POST /admin/users/{id}/role` | Redirected to login | **403 Forbidden** | ✓ (not their own role) |

- **Roles are assigned by the server.** New accounts always get `user`, and a `role` field added to the registration form is ignored. Only an admin can change a role, through the Admin Dashboard.
- **The policy covers every admin route.** `AdminOnly` is applied to the whole `/admin` route group, so a new admin page can't be added without protection by mistake.
- **Role changes take effect immediately.** Every request re-checks the user's role in the database. A demoted admin loses access straight away instead of keeping it until their cookie expires.
- **CSRF protection.** Forms that change state while logged in (role change, logout) need an anti-forgery token. That token is tied to the logged-in user, so one user's token can't be used for another user's session. This is on top of the `SameSite=Strict` cookie.
- **Admins can't change their own role**, so the system can't be left without an admin by accident.

### Creating the first admin

No admin password is stored in the code. To create the first admin, set it through environment variables before starting the app (PowerShell):

```powershell
$env:SeedAdmin__Username = "admin"
$env:SeedAdmin__Email    = "admin@example.com"
$env:SeedAdmin__Password = "<a long, unique passphrase>"
dotnet run --project src/SafeVault
```

The admin is created on first start if it doesn't already exist. After that, you can remove the variables.

### Tests (Step 4)

Activity 2 added 72 tests in these two files. (`dotnet test` now runs 221 tests across all three activities.)

- **`TestAuthentication`** checks that hashes are bcrypt and salted, and covers correct and wrong passwords, case sensitivity, unknown users, SQL injection in the login fields, lockout after 5 failures and its expiry after 15 minutes (using a fake clock), the counter resetting, hash upgrades, weak passwords, duplicate users and role assignment.
- **`TestAuthorization`** sends real HTTP requests as an anonymous visitor, a user and an admin. It checks redirects to login, 403 Forbidden for users on admin routes, users trying to promote themselves, a `role` field added to the registration form, admins promoting users, demoted admins losing access immediately, missing, forged and other users' anti-forgery tokens, invalid roles, a tampered cookie, stored XSS on the Admin Dashboard, and logout.

As a check that the tests work, three protections were removed one at a time: the `AdminOnly` policy, the per-request role re-check, and the anti-forgery check. Each time, the matching tests failed, and they passed again once the code was restored.

---

## Running it

```bash
cd SafeVault
dotnet test                              # run all tests
dotnet run --project src/SafeVault       # starts on https://localhost:7079
```

The login cookie is HTTPS-only. If the browser warns about the certificate, run `dotnet dev-certs https --trust` once. The app creates `safevault.db` (SQLite) on first run.

---

## Activity 3: Debugging and fixing vulnerabilities

An audit found seven issues (SV-01 to SV-07). All seven are fixed and covered by regression tests. Each test was seen failing before its fix and passing after it. [SECURITY-SUMMARY.md](SECURITY-SUMMARY.md) has the full write-up: how the audit was done, each finding with its severity, the fix, the test evidence, and the risks that were accepted.
