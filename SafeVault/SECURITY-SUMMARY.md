# SafeVault Security Summary (Activity 3)

This summary covers the security review done before deployment: how the codebase was audited, what was found, how each issue was fixed, and the tests that prove the fixes work.

**Result:** 7 vulnerabilities found and fixed (0 high, 3 medium, 3 low, 1 informational). The test suite grew from 161 to **221 tests**, and all of them pass.

---

## 1. How the audit was done

1. **Static review of the source code.** Searched for every place that builds SQL text (`CommandText`, interpolated or concatenated strings containing SQL keywords), every place that writes HTML (`Results.Content`, `WriteAsync`, `innerHTML`), every form field that is read, and how each endpoint is protected.
2. **Running the app and attacking it.** A temporary test sent attacks to the running app: replaying a copied login cookie after logout, a cross-site form post, 30 rapid login attempts, and a check of the headers on every response.
3. **Fuzzing every input.** Every SQL injection and XSS payload was sent through every field of every form. Null bytes, invisible Unicode characters, look-alike letters and a 100,000-character string were sent as well.
4. **Writing the test first.** For each issue, a test reproducing it was written and **seen to fail** on the unfixed code. Then the fix was applied and the test **seen to pass**.
5. **Checking the tests can catch regressions.** Fixes were temporarily undone to confirm the tests fail without them.

### Focus areas from the activity brief

| Area | What was checked | Result |
|---|---|---|
| **String concatenation in SQL** | All 15 SQL statements in `UserRepository.cs` | **No user input reaches SQL text.** Every value is sent as a typed parameter. One statement used string interpolation to insert a constant column list. That was safe, but it has been rewritten as a plain literal (SV-05). |
| **Input sanitization in form handling** | All 4 form handlers (`/submit`, `/login`, `/logout`, role change) | Validation itself was sound (allow-lists, length limits). Fuzzing found that **null bytes crashed every form handler** (SV-07). |
| **XSS in user-generated content** | All HTML and JSON output | HTML output was safe: every value is encoded automatically. **JSON output did not escape `<` and `>`** (SV-06). |

---

## 2. Vulnerabilities found and fixed

| ID | Severity | Vulnerability | Fix |
|---|---|---|---|
| SV-01 | Medium | A login cookie copied before logout kept working afterwards | Security stamp per user, changed on logout |
| SV-02 | Medium | Forms accepted posts from other websites (login CSRF) | Block cross-site POSTs using the `Sec-Fetch-Site` and `Origin` headers |
| SV-03 | Medium | No rate limiting on login or registration | 10 requests per minute per IP on `/login` and `/submit` |
| SV-04 | Low | Some responses could be cached or framed | `Cache-Control: no-store` and `X-Frame-Options: DENY` on every response |
| SV-05 | Info | SQL text built with string interpolation (of a constant) | Every SQL statement is now a plain string literal |
| SV-06 | Low | JSON responses didn't escape `<`, `>` and `&` | Strict JSON encoder |
| SV-07 | Low | Null bytes in any form crashed the server (500 error) | A shared form reader returns 400 instead |

### SV-01: Sessions stayed valid after logout (Medium)

- **Problem.** Logout only told the browser to delete its cookie. A copy taken earlier, for example by malware or on a shared computer, kept working for up to 30 minutes.
- **Reproduced.** Log in, copy the cookie, log out, then replay the copy. The result was **200 OK** (still logged in).
- **Fix.** Each user now has a random **security stamp** in the database, and it is copied into the cookie at login. On every request, `UserPrincipal.ValidateAsync` compares the two. Logging out (and any role change) replaces the stamp, so every older cookie for that user is rejected.
  Files: `Data/UserRepository.cs`, `Security/UserPrincipal.cs`, `Endpoints/AccountEndpoints.cs`.
- **Tests.** `SV01_CopiedCookie_IsRejected_AfterLogout`, `SV01_NewLogin_StillWorks_AfterLogout`.

### SV-02: Forms accepted cross-site submissions (Medium)

- **Problem.** The login and registration pages are static HTML, so they can't include an anti-forgery token. A malicious website could submit the login form in a visitor's browser with the attacker's credentials (**login CSRF**). The visitor would then be using the attacker's account without knowing it, and anything they entered would be visible to the attacker.
- **Reproduced.** `POST /login` with `Origin: https://evil.example`. The result was **302**: logged in.
- **Fix.** The new `CrossSiteRequestFilter` middleware rejects any POST, PUT, PATCH or DELETE with **403** if the browser reports it came from another site. It uses the `Sec-Fetch-Site` header, and falls back to comparing the `Origin` header on older browsers. This protects every form, not just the ones with tokens. Links from other sites (GET requests) still work.
  File: `Security/CrossSiteRequestFilter.cs`.
- **Tests.** `SV02_CrossSiteFormPost_IsRejected` (4 variants), `SV02_CrossSiteRegistration_IsRejected`, `SV02_SameOriginFormPost_IsAllowed` (3 variants), `SV02_CrossSiteGet_IsStillAllowed`.

### SV-03: No rate limiting on login and registration (Medium)

- **Problem.** The per-account lockout from Activity 2 stopped password guessing against a single account. But one client could still:
  - try one password against thousands of accounts (password spraying),
  - deliberately lock any account it knew the username of, or
  - create accounts in bulk.
- **Reproduced.** 30 rapid login attempts were all processed. None was throttled.
- **Fix.** ASP.NET Core's rate limiter allows **10 requests per minute per IP address** on `/login` and `/submit`. Anything over the limit gets **429 Too Many Requests** with `Retry-After: 60`.
  Files: `Program.cs`, `Endpoints/AccountEndpoints.cs`.
- **Tests.** `SV03_Login_IsRateLimited`, `SV03_Registration_IsRateLimited`.

### SV-04: Some responses could be cached or framed (Low)

- **Problem.** `/users/search` returned user data without `Cache-Control: no-store`, so a shared computer's browser cache could keep it. It also lacked `X-Frame-Options`, which older browsers need for clickjacking protection. The CSP `frame-ancestors` rule only protects modern browsers.
- **Fix.** Every response now sends `Cache-Control: no-store` and `X-Frame-Options: DENY`. The anti-forgery system's weaker `SAMEORIGIN` setting is turned off so it can't override `DENY`.
  File: `Program.cs`.
- **Tests.** `SV04_AuthenticatedResponses_AreNotCached`, `SV04_AllResponses_RefuseFraming`.

### SV-05: SQL text built with string interpolation (Informational)

- **Finding.** Five queries inserted a column-list constant into SQL text with `$"SELECT {UserColumns} ..."`. This was **not exploitable**, because the inserted value was a constant and never user input. But it is the same pattern as a real SQL injection flaw. It makes reviews harder and could become a real flaw if someone later inserted a variable.
- **Fix.** All SQL statements are now plain string literals. The search pattern is still passed as a parameter value, never as SQL text.
  File: `Data/UserRepository.cs`.
- **Tests.** The existing SQL injection tests in `TestUserRepository` and `TestAttackScenarios` still pass.

### SV-06: JSON responses didn't escape HTML characters (Low)

- **Problem.** ASP.NET Core's default JSON settings leave `<`, `>` and `&` unescaped. A username stored as `<script>…</script>` came back from `/users/search` exactly as stored. Browsers won't run it as delivered (it's sent as JSON with `nosniff` and a CSP), but a future page that inserted the JSON into HTML would be exposed to XSS. The Activity 1 notes wrongly said JSON output was already escaped. This audit caught that.
- **Found by** the new test `SearchJson_EscapesStoredScript`, which failed with `"username":"<script>alert('json')</script>"`.
- **Fix.** The strict `JavaScriptEncoder.Default` is now used for all JSON responses. The same value now comes back as `<script>…`.
  File: `Program.cs`.

### SV-07: Null bytes in a form crashed the server (Low)

- **Problem.** ASP.NET Core refuses to decode form values containing null bytes (`%00`) and throws `InvalidDataException`. None of the four form handlers caught it, so each one returned **500 Internal Server Error**. In development mode, the error page also exposed a full stack trace with file paths.
- **Found by** the fuzz test `UnusualInput_NeverCausesServerError("\0\0\0")`.
- **Fix.** All four handlers now use a shared `FormReader.TryReadFormAsync`, which returns **400 Bad Request** for a malformed form. The logout and role-change handlers read the form before the anti-forgery check, which also reads it.
  Files: `Endpoints/FormReader.cs`, `Endpoints/AccountEndpoints.cs`, `Endpoints/AdminEndpoints.cs`.
- **Tests.** `UnusualInput_NeverCausesServerError`, `NullBytes_InAuthenticatedForms_AreRejectedNotCrashing`. With the fix temporarily undone, both fail again.

---

## 3. Test evidence

| Stage | Result |
|---|---|
| Before fixes: new regression tests for SV-01 to SV-04 | **12 failed**, 6 passed. The 6 that passed check behaviour that must keep working, such as same-origin posts and links from other sites. |
| After fixes SV-01 to SV-05 | 179 of 179 passed |
| New attack-scenario suite added | **2 failed** (this is how SV-06 and SV-07 were found) |
| After fixes SV-06 and SV-07 | **221 of 221 passed** |

**New test files**

- **`TestSecurityFixes.cs`** has one or more regression tests per finding.
- **`TestAttackScenarios.cs`** simulates attacks:
  - every SQL injection and XSS payload through every registration field (username, email, password, confirm password) and both login fields, checking that nothing is reflected, no session is created and no server error occurs;
  - unusual input: null bytes, a byte-order mark, a right-to-left override, zero-width characters, look-alike letters, and 100,000-character values;
  - XSS stored in the database and returned through JSON;
  - **second-order SQL injection**: a payload stored in the database, read back, and reused in later queries, which must affect only its own row.

**Fixes temporarily undone to check the tests** (across Activities 1-3)

| Protection removed | Tests that failed |
|---|---|
| Parameterized query replaced with string concatenation | 6 |
| `AdminOnly` policy | 2 |
| Per-request role re-check | 1 |
| Anti-forgery check | 2 |
| Null-byte handling | 2 |

Each time the tests failed, and they passed again once the code was restored.

---

## 4. Accepted risks and deployment checklist

These issues remain on purpose and are documented here so they can be decided on before deployment.

- **Registration reveals whether a username or email is taken** (409 "already registered"). The usual fix is to send a confirmation email instead of showing an error. That needs email delivery, which SafeVault doesn't have. Rate limiting (SV-03) slows down attempts to list usernames.
- **Logout signs the user out on all devices.** This is a side effect of the security stamp (SV-01). It is safe, but users may notice it.
- **Rate limits are per server instance and per IP address.**
  - Behind a load balancer or reverse proxy, add `UseForwardedHeaders` so the real client IP is used. Otherwise every user shares the proxy's limit.
  - With several servers, use a shared rate-limit store.
  - Attackers spread across many IP addresses are still limited by the per-account lockout.
- **Before deploying:**
  - set `AllowedHosts` to the real domain name;
  - keep `ASPNETCORE_ENVIRONMENT=Production` so stack traces are never shown;
  - store the `SeedAdmin` password in a secret store;
  - store the ASP.NET Core Data Protection keys (which encrypt the login cookie) somewhere persistent and shared;
  - consider multi-factor authentication for admin accounts.

---

## 5. How AI assistance was used

This review was done with an AI coding assistant (Claude Code). It:

- searched the codebase for unsafe SQL construction, unencoded output and unprotected endpoints;
- wrote temporary probe tests to show that each suspected problem was real before changing any code;
- wrote a failing regression test for each issue, proposed the fix, and re-ran the full suite;
- generated the attack-scenario tests: payload lists, fuzz inputs and second-order injection;
- temporarily undid fixes to check that the tests catch regressions.

Two of the seven findings (SV-06 and SV-07) were **not** expected from the code review. Only the generated attack tests exposed them, which shows the value of testing on top of code review. The assistant also found that one of its own earlier statements was wrong: the Activity 1 notes claimed JSON output was escaped (SV-06).
