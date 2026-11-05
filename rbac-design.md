# Role-Based Access Control (RBAC) Designs

This activity has two RBAC designs:

1. A Learning Management System (LMS)
2. A Retail Bank

Each design follows the same steps as the examples: identify the roles, assign permissions with a reason for each, summarize them in a table, and explain how the design was made.

---

## Task 1: RBAC System for a Learning Management System (LMS)

### Step 1: Identify the Roles and Their Responsibilities

**Admin**

The Admin runs the platform as a whole. They create and remove user accounts, assign roles, create courses, assign instructors to courses, and configure system settings. Because they are responsible for the whole system, they need access to every part of it.

**Instructor**

Instructors teach courses. They publish course materials, create assignments, grade student work, and see who is enrolled in their courses.

- *Why limited to their own courses?* An instructor has no teaching reason to see another instructor's course content or another course's students and grades. Limiting them to their own courses protects student privacy and stops changes being made to courses they don't run.

**Student**

Students take courses. They need to see the materials and assignments for the courses they are enrolled in, submit their work, and see their own grades and feedback.

- *Why limited to their own data?* Grades are private. A student must never be able to see or change another student's grades or submissions.

**Guest**

Guests are visitors who are deciding whether to sign up. They can browse the course catalog, but they cannot enroll or see anything private, such as course content, submissions, grades or user details.

### Step 2: Assign Permissions to Each Role

**Admin**

- Create, edit, deactivate and delete user accounts.
- Assign and change user roles.
- Create, edit, archive and delete any course, and assign instructors to courses.
- View all courses, enrollments and grades.
- Configure system settings.

*Why?* Admins keep the platform working and secure, so they need full control over users, courses and settings.

**Instructor**

- Create and edit content for **their own** courses.
- Create, edit and delete assignments in their own courses.
- View the list of students enrolled in their own courses.
- View and grade submissions in their own courses, and give feedback.
- Post announcements to their own courses.

*Why?* These are the permissions an instructor needs to teach a course. They cannot manage users, change roles, change system settings, or access courses they are not assigned to.

**Student**

- Browse the course catalog and enroll in open courses.
- View materials and assignments for **their enrolled** courses.
- Submit their own assignments.
- View their own grades and feedback.

*Why?* Students need these permissions to take part in their courses. They cannot see other students' work or grades, and they cannot change course content or grades.

**Guest**

- View public course information: title, description, instructor name and syllabus overview.

*Why?* Guests only need enough information to decide whether to register. Read-only access to public information exposes no private data.

### Step 3: Summarize the RBAC Design in a Table

| Role | Permissions |
|---|---|
| **Admin** | Full access: manage users and roles, manage all courses and instructor assignments, view all enrollments and grades, configure system settings. |
| **Instructor** | Manage content and assignments for own courses, view enrolled students in own courses, grade submissions and give feedback, post announcements. |
| **Student** | Browse catalog and enroll, view enrolled course materials and assignments, submit own assignments, view own grades and feedback. |
| **Guest** | View public course information only (no enrollment, no private data). |

**Permission matrix**

| Permission | Admin | Instructor | Student | Guest |
|---|:---:|:---:|:---:|:---:|
| Manage users and roles | ✓ | | | |
| Configure system settings | ✓ | | | |
| Create / delete courses | ✓ | | | |
| Edit course content | ✓ (all) | ✓ (own) | | |
| Create / edit assignments | ✓ (all) | ✓ (own) | | |
| View enrolled students | ✓ (all) | ✓ (own) | | |
| Grade submissions | ✓ (all) | ✓ (own) | | |
| Enroll in courses | | | ✓ | |
| View course materials | ✓ (all) | ✓ (own) | ✓ (enrolled) | |
| Submit assignments | | | ✓ (own) | |
| View grades | ✓ (all) | ✓ (own courses) | ✓ (own) | |
| View public course catalog | ✓ | ✓ | ✓ | ✓ |

### Explanation of the Design Process

**How were the roles defined?**
Each role matches a distinct group of people in a typical online learning workflow. Admins run the platform, instructors teach, students learn, and guests browse before signing up.

**Why are the permissions assigned this way?**
Each role gets only the permissions its job requires. This is the **principle of least privilege**. Instructor and Student permissions are also limited to the courses they are connected to (*own* or *enrolled*), so having a role does not grant access to the whole system.

**How does this system protect data?**
Grades, submissions and personal details are visible only to the student they belong to, that student's instructor, and the Admin. Guests see public information only, and only Admins can change roles or settings. This makes it harder for one compromised or careless account to expose or change other users' data.

---

## Task 2: RBAC System for a Retail Bank

### Step 1: Identify the Roles and Their Responsibilities

**Admin**

The Admin manages the bank's system. They open, close and freeze accounts, maintain customer data, correct or reverse transactions, and manage staff user accounts and roles. They need broad access to keep the bank running.

**Teller**

Tellers serve customers at the branch. They process deposits, withdrawals and transfers, and they verify that the customer in front of them owns the account.

- *Why no access to full account histories?* Processing a transaction only needs the customer's identity, the account, and the current balance. A full transaction history shows a customer's private financial life, and a teller does not need it to do their job.

**Auditor**

Auditors check that the bank's systems and staff are following the rules. They review system logs and transaction records to find errors, fraud or policy violations.

- *Why no sensitive customer details?* An audit looks at *what happened* (amounts, times, which staff member did what), not *who the customer is*. Customer identifiers can be masked (for example, `****1234`) so auditors can follow activity without seeing personal information.
- Auditors have **read-only** access. Someone who checks the records must not be able to change them.

**Customer**

Customers need to see their own accounts so they know their balances and can check their transactions. They must never see another customer's information.

### Step 2: Assign Permissions to Each Role

**Admin**

- Open, close, freeze and unfreeze customer accounts.
- View and update customer personal data.
- View all accounts and full transaction histories.
- Correct or reverse transactions.
- Create and manage staff user accounts and assign roles.

*Why?* Admins are responsible for the bank's accounts and data as a whole, so they need full management permissions. Admin actions are recorded in the system logs, so Auditors can review them.

**Teller**

- Look up a customer's account to verify identity (name, account number, ID check).
- View the current balance of an account.
- Process deposits, withdrawals and transfers.

*Why?* These are the permissions needed to serve a customer at the counter. Tellers cannot view full transaction histories, change customer personal data, open or close accounts, or reverse transactions.

**Auditor**

- View system logs, such as logins, staff actions and permission changes (read-only).
- View transaction records with customer details masked (read-only).
- Generate audit reports.

*Why?* Auditors need to see activity across the whole system to detect problems. Read-only access protects the integrity of the evidence, and masking customer data protects privacy.

**Customer**

- View their own account details and balances.
- View their own transaction history.

*Why?* Customers need visibility into their own money. Limiting this to their own accounts keeps every other customer's data private.

### Step 3: Summarize the RBAC Design in a Table

| Role | Permissions |
|---|---|
| **Admin** | Full access: manage accounts (open/close/freeze), view and update customer data, view all transactions, correct or reverse transactions, manage staff users and roles. |
| **Teller** | Verify customer identity, view current balance, process deposits, withdrawals and transfers. No full account history. |
| **Auditor** | Read-only access to system logs and transaction records (customer details masked), generate audit reports. |
| **Customer** | View own account details, balances and transaction history. |

**Permission matrix**

| Permission | Admin | Teller | Auditor | Customer |
|---|:---:|:---:|:---:|:---:|
| Open / close / freeze accounts | ✓ | | | |
| Manage staff users and roles | ✓ | | | |
| View and update customer personal data | ✓ | | | |
| Verify customer identity | ✓ | ✓ | | |
| View current balance | ✓ | ✓ | | ✓ (own) |
| Process deposits / withdrawals / transfers | ✓ | ✓ | | |
| Correct / reverse transactions | ✓ | | | |
| View full transaction history | ✓ | | ✓ (masked, read-only) | ✓ (own) |
| View system logs | ✓ | | ✓ (read-only) | |
| Generate audit reports | | | ✓ | |

### Explanation of the Design Process

**How were the roles defined?**
The roles match how a retail bank actually operates. Admins manage the system, tellers handle day-to-day transactions, auditors provide independent oversight, and customers access their own money.

**Why are the permissions assigned this way?**
Each role gets only what it needs (**least privilege**). The design also uses **separation of duties**. The people who move money (Tellers and Admins) are not the people who check that the movements were correct (Auditors). Auditors can see but not change. This makes fraud harder, because no single role can both carry out an action and hide it.

**How does this system protect data?**
- Full transaction histories, which are the most sensitive financial data, are limited to Admins, masked views for Auditors, and each customer's own records.
- Tellers can process transactions without seeing a customer's full financial history.
- Auditors can follow activity without seeing personal details.
- Every staff action is logged and open to review.

Together, these controls reduce the damage a single compromised account or insider could cause.
