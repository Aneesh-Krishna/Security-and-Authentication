# JWT Structure Analysis

A JSON Web Token (JWT) has three Base64URL-encoded parts, separated by periods:

```
HEADER.PAYLOAD.SIGNATURE
```

To decode a token, split it on `.` and Base64URL-decode the first two parts. The signature is binary data, so it does not decode into readable text. The helper below was used for both tasks:

```python
import base64, json

def decode_part(part):
    part += "=" * (-len(part) % 4)          # restore Base64 padding
    return json.loads(base64.urlsafe_b64decode(part))

header, payload, signature = token.split(".")
print(decode_part(header))
print(decode_part(payload))
```

---

## Task 1: Analyze a JWT for an E-Commerce System

**JWT provided:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiI1Njc4OTAiLCJyb2xlIjoidXNlciIsImV4cCI6MTY5MjIzMDAwfQ.
Hx73oTzVZj5lfZlyyRcAJo3hH9M3VBB9-LD9ACBRUjk
```

### Step 1: Analyze the Header

**Encoded:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

**Decoded Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Explanation:**

- **alg:** `HS256` (HMAC-SHA256), a *symmetric* algorithm. The same secret key is used to create the signature and to verify it.
- **typ:** `JWT` identifies the token as a JSON Web Token.

**Why important?** The header tells the server how to verify the signature. The server should only accept the algorithm it expects (`HS256`). It should not trust whatever algorithm the header claims. Otherwise an attacker could change it to `"alg": "none"` and skip signature checking.

### Step 2: Analyze the Payload

**Encoded:** `eyJzdWIiOiI1Njc4OTAiLCJyb2xlIjoidXNlciIsImV4cCI6MTY5MjIzMDAwfQ`

**Decoded Payload:**

```json
{
  "sub": "567890",
  "role": "user",
  "exp": 169223000
}
```

**Explanation:**

- **sub (subject):** User ID `567890`. This identifies which customer the token belongs to.
- **role:** `user`, a standard customer. The platform uses this to allow customer actions (browsing, placing orders, viewing their own order history) and to deny admin or staff functions.
- **exp (expiration):** `169223000`, a Unix timestamp (seconds since 1 January 1970, UTC). After this time the server must reject the token.

**Observation about `exp`:** `169223000` has only 9 digits, and it converts to **13 May 1975, 14:23:20 UTC**. That date is in the past, so a server checking `exp` would reject this token immediately as expired. The value was most likely meant to be `1692230000` (10 digits), which converts to **16 August 2023, 23:53:20 UTC**. Either way, the token has expired as of today. This shows why `exp` values must be generated carefully: one missing digit makes the token useless.

**About the 24-hour validity:** The payload has no `iat` (issued-at) claim, so the 24-hour lifetime cannot be confirmed from the token itself. If the token was issued 24 hours before `exp`, it was issued on 15 August 2023 at 23:53:20 UTC (assuming the intended value `1692230000`). Adding an `iat` claim would make the token's lifetime easy to check.

**Why important?** The payload carries the claims the server uses to identify the user (`sub`), decide what they can do (`role`), and decide how long the token is trusted (`exp`). Note that the payload is only **encoded, not encrypted**. Anyone who has the token can read it, so it must never contain secrets such as passwords or card numbers.

### Step 3: Analyze the Signature

**Encoded Signature:** `Hx73oTzVZj5lfZlyyRcAJo3hH9M3VBB9-LD9ACBRUjk`

This decodes to 32 bytes (256 bits), which is the output size of HMAC-SHA256. That matches the `HS256` algorithm in the header.

**How it is created:**

```
signature = HMACSHA256(
    base64UrlEncode(header) + "." + base64UrlEncode(payload),
    secret_key
)
```

**How it protects the token:**

- When the server receives the token, it recalculates the signature from the header and payload using its own secret key, and compares the result with the signature in the token.
- Suppose an attacker edits the payload, for example changing `"role": "user"` to `"role": "admin"` or extending `exp`. The recalculated signature will no longer match, and the server rejects the token.
- The attacker cannot create a valid new signature without the secret key, which only the server holds.

**Why important?** The signature ensures **integrity** (the claims have not been changed) and **authenticity** (the token was issued by the server). It does **not** provide confidentiality, because the payload is still readable.

### Summary of Findings

| Component | Decoded Content | Explanation |
|---|---|---|
| **Header** | `{"alg": "HS256", "typ": "JWT"}` | Signed with HMAC-SHA256 using a shared secret key; the token type is JWT. |
| **Payload** | `{"sub": "567890", "role": "user", "exp": 169223000}` | User ID `567890`, role `user` (standard customer), expiration time `169223000` (13 May 1975, probably a typo for `1692230000` = 16 Aug 2023, 23:53:20 UTC). The token is expired. |
| **Signature** | `Hx73oTzVZj5lfZlyyRcAJo3hH9M3VBB9-LD9ACBRUjk` | A 256-bit HMAC of the header and payload. Any change to the role, ID or expiry makes it invalid, so tampering is detected. |

---

## Task 2: Analyze a JWT for a Healthcare Application

**JWT provided:**

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTUwIiwicm9sZSI6ImRvY3RvciIsImV4cCI6MTY4MjQ2NjAwMH0.
dsg5KlRsdpQZn1uvKjMf2M3Kw8E3ljUlShVlxVc43F4
```

### Step 1: Analyze the Header

**Encoded:** `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`. This is identical to Task 1.

**Decoded Header:**

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Explanation:**

- **alg:** `HS256` (HMAC-SHA256), a symmetric signing algorithm that uses a secret key known only to the server.
- **typ:** `JWT` identifies the token as a JSON Web Token.

**Why important?** The header tells the server which algorithm to use to verify the signature. In a healthcare system, the server should accept only `HS256` (or whatever algorithm it is configured for). Rejecting anything else matters here, because a forged token could expose protected patient data.

### Step 2: Analyze the Payload

**Encoded:** `eyJzdWIiOiIxMjM0NTUwIiwicm9sZSI6ImRvY3RvciIsImV4cCI6MTY4MjQ2NjAwMH0`

**Decoded Payload:**

```json
{
  "sub": "1234550",
  "role": "doctor",
  "exp": 1682466000
}
```

**Explanation:**

- **sub (subject):** User ID `1234550`. This identifies which doctor the token belongs to.
- **role:** `doctor`. This grants doctor permissions, such as viewing and updating records for assigned patients, viewing test results and prescribing medications. It does not grant admin functions.
- **exp (expiration):** `1682466000`, which converts to **25 April 2023, 23:40:00 UTC**. After this time the server must reject the token.

**About the 12-hour validity:** There is no `iat` claim, so the 12-hour lifetime cannot be confirmed from the token alone. If the token was issued 12 hours before `exp`, it was issued on **25 April 2023 at 11:40:00 UTC**. As of today, the token has expired.

**Why important?** A short lifetime matters especially for a doctor, who has access to highly sensitive patient data. If this token were stolen, an attacker could only use it until it expires, rather than indefinitely. Like any JWT payload, these claims are readable by anyone holding the token. That is acceptable for an ID and a role, but patient information must never be placed in the payload.

### Step 3: Analyze the Signature

**Encoded Signature:** `dsg5KlRsdpQZn1uvKjMf2M3Kw8E3ljUlShVlxVc43F4`

This also decodes to 32 bytes (256 bits), which matches HMAC-SHA256.

**How it ensures security:**

- The signature is calculated over `base64UrlEncode(header) + "." + base64UrlEncode(payload)` using the server's secret key.
- On each request, the server recalculates the signature and compares it with the one in the token. If they match, the claims are trusted.
- Suppose an attacker changes `"role": "doctor"` to `"role": "admin"` to gain system control, changes `sub` to impersonate another doctor, or pushes `exp` later to keep using a stolen token. The recalculated signature would not match, and the token would be rejected.
- Without the secret key, a valid signature cannot be created for modified claims. For this reason, the key must be long, random and stored securely on the server only.

### Summary of Findings

| Component | Decoded Content | Explanation |
|---|---|---|
| **Header** | `{"alg": "HS256", "typ": "JWT"}` | Signed with HMAC-SHA256 using a shared secret key; the token type is JWT. |
| **Payload** | `{"sub": "1234550", "role": "doctor", "exp": 1682466000}` | User ID `1234550`, role `doctor`, expiration time `1682466000` = 25 April 2023, 23:40:00 UTC (12-hour validity, issued around 11:40 UTC). The token is expired. |
| **Signature** | `dsg5KlRsdpQZn1uvKjMf2M3Kw8E3ljUlShVlxVc43F4` | A 256-bit HMAC of the header and payload. It detects any change to the doctor's ID, role or expiry, which protects access to patient data. |

---

## Key Takeaways

1. **Header:** declares the signing algorithm. The server must enforce the algorithm it expects rather than trusting the header.
2. **Payload:** carries the identity (`sub`), the permissions (`role`) and the lifetime (`exp`). It is encoded, not encrypted, so it must never hold secrets.
3. **Signature:** guarantees that the header and payload have not been changed and were issued by the holder of the secret key. Without the key, tampering is detected.
4. **Expiration:** limits how long a stolen token can be misused. Shorter lifetimes are better for more sensitive roles, such as a doctor compared with a shopper.
