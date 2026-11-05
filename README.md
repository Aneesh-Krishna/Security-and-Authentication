# Security and Authentication: Course Project

This repository contains my work for the Security and Authentication course. The main submission is **[SafeVault](SafeVault/)**, an ASP.NET Core (.NET 10) web application secured over three activities, with an NUnit test suite of **221 tests, all passing**.

## Where to find each rubric item

| Rubric item | Where to look |
|---|---|
| **GitHub repository** | This repository |
| **Secure code for input validation and SQL injection prevention** | [InputValidator.cs](SafeVault/src/SafeVault/Security/InputValidator.cs) (allow-list validation and sanitizing) · [UserRepository.cs](SafeVault/src/SafeVault/Data/UserRepository.cs) (parameterized queries only) · [SafeHtml.cs](SafeVault/src/SafeVault/Security/SafeHtml.cs) (automatic output encoding) |
| **Authentication and authorization, including RBAC** | [AuthService.cs](SafeVault/src/SafeVault/Security/AuthService.cs) (login, lockout) · [PasswordHasher.cs](SafeVault/src/SafeVault/Security/PasswordHasher.cs) (bcrypt) · [Roles.cs](SafeVault/src/SafeVault/Security/Roles.cs) and [AdminEndpoints.cs](SafeVault/src/SafeVault/Endpoints/AdminEndpoints.cs) (`user` and `admin` roles, admin-only dashboard) |
| **Debugged and resolved vulnerabilities such as SQL injection and XSS** | [SECURITY-SUMMARY.md](SafeVault/SECURITY-SUMMARY.md), sections 1-2: 7 findings (SV-01 to SV-07), each with its fix |
| **Tests that verify the application's security** | [tests/SafeVault.Tests/](SafeVault/tests/SafeVault.Tests/), especially [TestInputValidation.cs](SafeVault/tests/SafeVault.Tests/TestInputValidation.cs), [TestAuthorization.cs](SafeVault/tests/SafeVault.Tests/TestAuthorization.cs) and [TestAttackScenarios.cs](SafeVault/tests/SafeVault.Tests/TestAttackScenarios.cs) |
| **Summary of vulnerabilities, fixes and AI assistance** | [SECURITY-SUMMARY.md](SafeVault/SECURITY-SUMMARY.md). Section 5 describes how AI assistance was used. |

[SafeVault/README.md](SafeVault/README.md) explains the design of each activity in more detail.

## Running the tests

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download).

```bash
cd SafeVault
dotnet test
```

Expected result: `Passed! - Failed: 0, Passed: 221`.

To try the app in a browser, run `dotnet run --project src/SafeVault` and open `https://localhost:7079`. If the browser warns about the certificate, run `dotnet dev-certs https --trust` once.

## Earlier course exercises

These files are from the shorter exercises earlier in the course. They aren't part of SafeVault.

| File | Exercise |
|---|---|
| [registration.html](registration.html) | HTML5 form validation, with a JavaScript password-match check |
| [rbac-design.md](rbac-design.md) | RBAC designs for a learning management system and a retail bank |
| [jwt-analysis.md](jwt-analysis.md) | Decoding the header, payload and signature of two JWTs |
| [api-security-plan.md](api-security-plan.md) | JWT and role requirements for API routes |
