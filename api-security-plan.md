# API Endpoint Security Planning with JWT

This activity plans the security for two APIs: a social media platform and a Learning Management System (LMS). For each route, the plan says whether a JWT must be validated, which roles can call the route, and which claims the server checks.

**What "JWT validation" means in this plan.** For every route marked *Required*, the server must do all of the following before checking roles:

1. Check that the signature is valid, using the server's secret key.
2. Check that the algorithm is the one the server expects (for example `HS256`). It must not trust the token's own `alg` value, which an attacker could set to `none`.
3. Check that the token has not expired: the `exp` time must be in the future.
4. Read the `role` and `sub` (user ID) claims from the verified token. These values must never be taken from the request body or URL.

If any check fails, the server responds **401 Unauthorized**. If the token is valid but the role or ownership check fails, the server responds **403 Forbidden**.

---

## Task 1: Plan API Security for a Social Media Platform

### Routes

- `GET /users/{id}`: Returns profile information for a specific user.
- `POST /posts`: Creates a new post.
- `DELETE /posts/{id}`: Deletes a specific post.

### Step 1: Identify Which Routes Require JWT Validation

**GET /users/{id}: Required.**
Profiles on a social platform contain personal information, such as email, birthday, friends list and private posts. What a requester is allowed to see depends on *who they are*: the profile owner, a friend or follower, or a stranger. The server can only make that decision if it knows the requester's identity, and the JWT provides it. Requiring a token also makes it harder for anonymous bots to scrape user profiles in bulk.

**POST /posts: Required.**
Creating content must be tied to a real, logged-in account. Otherwise anyone could post anonymously or post *as* another user, which would allow spam and impersonation.

**DELETE /posts/{id}: Required.**
Deleting is a destructive action that cannot be undone. The server must know exactly who is asking, so it can check that they are allowed to delete *this* post.

### Step 2: Specify Roles or Claims Needed for Access

**GET /users/{id}**

- **Roles:** `user`, `moderator`, `admin`.
- **Claims:** `sub` (the requester's user ID).
  - If `sub` equals `{id}`, the requester is the owner and sees their full profile, including private fields.
  - If `sub` is different, the requester sees only the fields the owner's privacy settings allow (for example, public fields, or extra fields for friends).
  - `moderator` and `admin` can see additional account details for moderation purposes.

**POST /posts**

- **Roles:** `user`, `moderator`, `admin`. Any logged-in account can post.
- **Claims:** `sub`. The server sets the post's author ID from the token's `sub` claim and ignores any author ID sent in the request body. This prevents posting as someone else.

**DELETE /posts/{id}**

- **Roles:**
  - `user` can delete **only their own** posts.
  - `moderator` and `admin` can delete **any** post, for example to remove content that breaks the rules.
- **Claims:** `sub`. For the `user` role, the server looks up the post and allows the delete only if `post.authorId == sub`.

### Step 3: Why These Restrictions Are Necessary

- **Authentication on every route** means each action can be traced to a real account. This discourages spam and abuse, and makes them possible to investigate.
- **Using `sub` from the verified token** stops impersonation. A user cannot claim to be someone else, because changing the token would break its signature.
- **Ownership checks on DELETE** stop users from deleting other people's posts. Only the author, or a moderator acting on a policy violation, can remove content.
- **Field-level filtering on profiles** respects each user's privacy settings while still letting profiles be viewed.

### Summary of Findings

| Route | JWT Validation | Roles | Claims |
|---|---|---|---|
| `GET /users/{id}` | Required | `user`, `moderator`, `admin` | `sub`. The full profile is returned if `sub == {id}`; otherwise only the fields allowed by the owner's privacy settings. |
| `POST /posts` | Required | `user`, `moderator`, `admin` | `sub`, used as the post's author ID (never taken from the request body). |
| `DELETE /posts/{id}` | Required | `user` (own posts only), `moderator`, `admin` (any post) | `sub`. For `user`, `sub` must match the post's author ID. |

---

## Task 2: Plan API Security for a Learning Management System (LMS)

### Routes

- `GET /courses`: Lists all available courses.
- `POST /assignments`: Creates a new assignment.
- `GET /grades/{id}`: Returns grades for a specific student.

### Step 1: Identify Which Routes Require JWT Validation

**GET /courses: Not required.**
The course catalog is public information, such as titles, descriptions and instructors. Guests need to browse it before they sign up, just as shoppers browse products before logging in. Nothing private is returned.

**POST /assignments: Required.**
Creating an assignment changes course content that students depend on. Only authenticated instructors or admins should be able to do this.

**GET /grades/{id}: Required.**
Grades are private educational records. They must be visible only to the student they belong to and to the staff responsible for that student.

### Step 2: Specify Roles or Claims Needed for Access

**GET /courses**

- No JWT validation needed. The route is public.

**POST /assignments**

- **Roles:** `instructor`, `admin`. The `student` and guest roles are denied.
- **Claims:** `sub` (the instructor's user ID).
  - For `instructor`, the server checks that the `courseId` in the request belongs to a course this instructor teaches. Instructors can only create assignments in their own courses.
  - `admin` can create assignments in any course.

**GET /grades/{id}**

- **Roles:** `student`, `instructor`, `admin`.
- **Claims:** `sub`.
  - `student` can view grades only if `sub == {id}`, meaning only their own grades.
  - `instructor` can view grades only if student `{id}` is enrolled in a course this instructor teaches. The results are limited to that instructor's courses.
  - `admin` can view any student's grades.

### Step 3: Why These Restrictions Are Necessary

- **A public catalog** lets prospective students explore courses without creating an account, and it exposes no private data.
- **Role restrictions on POST /assignments** stop students from creating fake assignments. **Course ownership checks** stop instructors from changing courses they don't teach.
- **Ownership checks on GET /grades/{id}** protect student privacy. Without the `sub == {id}` check, any logged-in student could change the `{id}` in the URL and read classmates' grades. This kind of attack is called an Insecure Direct Object Reference (IDOR).
- These rules match the LMS RBAC design from Activity 2. Guests browse, students see only their own data, instructors manage only their own courses, and admins have full access.

### Summary of Findings

| Route | JWT Validation | Roles | Claims |
|---|---|---|---|
| `GET /courses` | Not required | None (public) | None. |
| `POST /assignments` | Required | `instructor`, `admin` | `sub`. Instructors must teach the course the assignment is for. |
| `GET /grades/{id}` | Required | `student`, `instructor`, `admin` | `sub`. Students: `sub == {id}`. Instructors: the student must be enrolled in their course. Admins: any student. |

---

## Key Takeaways

1. **Public data does not need a JWT**, but anything personal, or anything that changes data, does.
2. **Roles answer "what kind of user is this?"** Claims such as `sub`, combined with ownership checks, answer "is this *their* data?". Most routes need both.
3. **Trust the token, not the request.** The user's identity must always come from the verified `sub` claim, never from a body field or URL parameter the user controls.
4. **Use the right error code.** A missing or invalid token returns 401; a valid token without permission returns 403.
