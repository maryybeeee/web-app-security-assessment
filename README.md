# Web Application Security Assessment

**Type:** Academic penetration testing case study
**Environment:** Isolated lab web application (no real user data)
**Methodology reference:** OWASP Testing Guide / PTES (Penetration Testing Execution Standard)
**Status:** File Upload vector — mitigated. SQL Injection vector — assessed (2 endpoints tested).

---

## Executive Summary

This report documents a controlled security assessment of a web application deployed in an academic lab environment. Two attack vectors were evaluated: **arbitrary file upload** (targeting the receipt/document upload endpoint) and **SQL Injection** (targeting the login and registration endpoints).

The file upload vector was tested end-to-end: the server successfully neutralized the attempted attack by renaming uploaded files and stripping executable extensions, preventing remote code execution. The SQL Injection vector was tested against two distinct fields: the login endpoint's email field rejected the payload through format validation before it reached the database layer, while the registration endpoint's name field accepted the payload but stored it as inert literal text — no query error, no unexpected execution — indicating the use of parameterized queries.

Overall, the application demonstrates multiple layers of effective input-handling controls across different endpoints and validation strategies.

---

## 1. Scope & Rules of Engagement

- **Authorized environment:** Web application deployed by a fellow student's team as part of an academic project (9th-semester coursework). No real user data is stored in the system.
- **Authorization:** Verbal and written permission obtained from the team member responsible for the system, confirming it was a test deployment intended for security evaluation.
- **Target (anonymized):** `target-system.internal` — a `.ts.net` (Tailscale) hosted test instance.
- **Objective:** Evaluate the security of the authentication module and the receipt/document upload endpoint (`/dashboard/uploads/comprobantes/`).
- **Out of scope:** Any production system, any system outside the explicitly authorized test deployment, denial-of-service testing.

---

## 2. Reconnaissance

**Passive:**
- Reviewed exposed front-end source code and application structure via browser DevTools.
- Identified client-side JavaScript bundles and endpoint naming conventions (`/api/portal/login`, `/dashboard/uploads/comprobantes/`).

**Active:**
- Inspected HTTP requests and responses using Chrome DevTools (Network tab).
- Sent manual `fetch()` requests from the browser console to test endpoint behavior directly.

---

## 3. Scanning & Enumeration

- **Server identified:** `nginx/1.31.3` (via response headers).
- **Response mapping:** Analyzed JSON response structures from the backend, identifying fields such as `ruta_archivo`, `tipo`, `monto`, `nombre`, `matricula`, and others exposed in registration/upload responses.
- **Resource enumeration:** Attempted direct access to stored file paths to determine whether uploaded files were reachable and how they were renamed.

---

## 4. Vulnerability Analysis & Exploitation Attempts

### 4.1 File Upload — Remote Code Execution Attempt

**Technique:** Uploaded a file using a double extension (`exploit.php.jpg`), created by concatenating a valid JPEG image with a basic PHP web shell payload (`system($_GET['cmd'])`), attempting to get the server to interpret it as an executable PHP script.

**Intent:** If successful, this would allow remote command execution through a URL parameter (e.g., `?cmd=whoami`).

**Server behavior (defense observed):**
The backend accepted the upload but renamed the file and enforced a `.jpg` extension on the stored object (e.g., `/uploads/comprobantes/1787906546475-438766520.jpg`).

**Result:** The vulnerability was neutralized. Because the final stored file has a `.jpg` extension, the web server (Nginx) treats it as a static resource and does not invoke the PHP interpreter — the file is served as raw bytes/image data, not executed as code.

**Verification attempts:**
- Appending `?cmd=whoami` to the stored file's URL had no effect — GET parameters are ignored when no interpreter processes the file.
- Base64-decoding the stored file client-side only revealed the raw uploaded bytes; it did not trigger any server-side evaluation.

![File upload accepted, extension stripped to .jpg](screenshots/screenshot1.png)
![Execution attempt blocked - 404 Not Found](screenshots/screenshot2.png)

### 4.2 SQL Injection — Authentication Endpoint

**Technique:** Submitted a classic authentication bypass payload through the login form.

**Payload:**
```json
{
  "email": "test@gmail.com' OR '1'='1",
  "password": "123"
}
```

**Result:** `400 Bad Request` — `"El correo electrónico no tiene un formato válido."`

**Analysis:** The application performs server-side format validation on the email field (likely a regex-based check) before any data reaches the query layer. The malformed payload is rejected at the input-validation stage, never reaching the database layer. This is an effective mitigation for this specific field and vector.

![SQL injection attempt on login - rejected by email format validation](screenshots/screenshot3.png)

### 4.3 SQL Injection — Registration Endpoint

**Technique:** Submitted a payload targeting the `nombre` (name) field, which — unlike the login endpoint's email field — does not enforce strict client-side format validation (confirmed via DevTools inspection: the input element has no `pattern`, `maxlength`, or format restriction attributes).

**Payload:**
```json
{
  "nombre": "tilinsito'; SELECT 1--",
  "apellido_paterno": "cole",
  "apellido_materno": "tiline",
  "email": "[redacted-test-account]",
  "password": "[redacted]",
  "estado_civil": "Viudo(a)",
  "grado_estudios": "Licenciatura",
  "...": "..."
}
```

**Result:** Registration succeeded (`200`/`201`). The account was created successfully, and the payload was stored and rendered **as literal text** — visible unmodified in the post-login dashboard greeting (`¡Hola, tilinsito'; !`) and in the account's profile data.

**Analysis:** No SQL syntax error was triggered, no unexpected query executed, and the application did not crash or behave unexpectedly. This strongly suggests the backend uses **parameterized queries or an ORM** for the registration `INSERT` operation, treating user input strictly as data rather than executable SQL. This is an effective mitigation against classic string-concatenation-based SQL Injection on this field.

**Note:** This finding is interesting in contrast to 4.2 — the login endpoint blocks malicious input *before* it reaches the database (via format validation), while the registration endpoint allows the input through but neutralizes it *at the query layer* (via parameterization). Both are valid defense strategies, but relying on client/format validation alone (as seen on the email field) is generally considered weaker than parameterization, since format validation can be bypassed by adjusting the payload to match the expected pattern (e.g., `injection@test.com'--`), whereas parameterized queries neutralize the injection regardless of payload shape.

![Registration succeeded - payload stored as literal text, rendered in dashboard greeting](screenshots/screenshot4.png)

---

## 5. Impact Assessment (Theoretical)

Had the file upload vector succeeded, an attacker could have achieved remote code execution with the privileges of the web server process, potentially leading to full system compromise, data exfiltration, or lateral movement within the hosting environment. The observed mitigation (extension stripping / renaming) is an effective control against this specific technique, though it should be paired with the additional defenses listed below for defense-in-depth.

---

## 6. Recommendations

1. **Rename all uploaded files using generated identifiers (e.g., UUIDs)** and enforce output extensions from an explicit allow-list — never trust the client-provided filename or extension.
2. **Validate file content by magic bytes on the backend**, not just MIME type or extension, to catch polyglot files before they are stored.
3. **Disable script execution in the uploads directory** at the web server configuration level (Nginx/Apache), so that even a misconfigured upload path cannot result in code execution.
4. **Maintain parameterized queries / ORM usage across all database write operations** — the registration endpoint's resistance to SQL Injection despite accepting unrestricted input confirms this is already in place; ensure it remains consistent as new endpoints are added.
5. **Do not rely on client-side format validation as a security control** — the login endpoint's email format check is a good UX feature, but format validation alone can often be bypassed by crafting a payload that satisfies the expected pattern (e.g., appending an injection payload after a validly-formatted email). Parameterized queries, as already used on the registration endpoint, should be the primary defense — format checks are a secondary/UX layer, not a security boundary.
6. **Serve uploaded files through a controlled, authenticated endpoint** rather than direct static file paths, to reduce the attack surface for enumeration.

---

## 7. Lessons Learned

This was my first hands-on, semi-independent security assessment outside of a guided lab (DVNA). Key takeaways:

- Understanding *why* a mitigation works (extension stripping preventing PHP interpretation, parameterized queries neutralizing injection payloads) is more valuable than just knowing an attack "didn't work."
- **Not all defenses are equal.** Comparing the login and registration endpoints taught me that format validation (login) and parameterized queries (registration) are both valid, but they protect against different things — format validation can be bypassed with a cleverly shaped payload, while parameterization neutralizes injection regardless of input shape. A field that "looks less protected" (no client-side restrictions) isn't necessarily more vulnerable if the backend handles it correctly.
- Documentation discipline (capturing evidence *as you test*, not after) is a skill in itself — I'm still improving at capturing evidence in the moment rather than reconstructing it afterward.
- Testing one variable at a time (one field, one endpoint) produces much clearer, more defensible findings than changing multiple things at once.

---

## Disclaimer

This assessment was conducted with explicit authorization from the system's responsible party, against a non-production, academic test environment containing no real user data. This repository is for educational and portfolio purposes only.