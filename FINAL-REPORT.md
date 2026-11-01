# Term Project Report — Secure Build

> Fill in every section. Keep the headings. Total **100 pts** (see rubric at the end).
> This is **team work** (2–3). Do not share your report with other teams.

## Cover

| Field | Value |
|---|---|
| Team name | Bits |
| Members (name + ID) | Kay Khine Maw (#6631503060) & Nway Nway Zay Ya (#6631503081) |
| Target application | NoteVault |
| Repository URL | https://github.com/nwaynwayzayya/software-security-project-bits |
| Date | |

## AI-tool usage disclosure
*Academic integrity: state how you used any AI tools (ChatGPT, Copilot, etc.) — e.g. searching, coding, translating, drafting. "None" is a valid answer.*

| Tool | How it was used |
|---|---|
| GitHub Copilot / Copilot SDK | Assisted with repository inspection, security test planning, command explanations, and report organization. The team performed the local testing and reviewed the resulting evidence. |

---

## 1. Executive Summary
*(½ page) What the app is, how many findings by severity, and the overall risk before vs. after your fixes.*

---

## 2. System Scope & Function
- What the application does; in-scope components and endpoints.
- **Data-Flow Diagram (DFD):** processes, data stores, external entities, **trust boundaries** (insert image).

NoteVault is a Flask web application that supports local user registration, login, note creation, note retrieval, note search, an administrator view, and an export convenience endpoint. The application stores users and notes in SQLite and runs locally in a Docker container.

The in-scope components are:

- `app.py`: Flask routes, authentication, authorization, database access, rendering, and export behavior.
- `requirements.txt`: Python dependency versions.
- `Dockerfile`: Container image construction and runtime configuration.
- `docker-compose.yml`: Local container execution.
- `.github/workflows/security-ci.yml`: SAST, SCA, secret scanning, container scanning, and SBOM generation.
- `FINAL-REPORT.md`: Security findings, remediation evidence, and supply-chain documentation.

The in-scope endpoints are `/`, `/register`, `/login`, `/logout`, `/notes`, `/api/notes/<id>`, `/search`, `/admin`, and `/export`.

### Baseline environment

- Repository: `nwaynwayzayya/software-security-project-bits`
- Branch: `main`
- Baseline tag: `vulnerable-baseline`
- Baseline commit: `b3a1e5d` followed by the full commit hash from `evidence/baseline/baseline-commit.txt`
- Runtime: Docker Compose
- Local URL: `http://localhost:8080`
- Team marker: configured through `TEAM_ID`; the value itself is not a secret and should be recorded only if your course requires it

---

## 3. Threat Model — STRIDE  *(20 pts)*

| Element / data flow | S | T | R | I | D | E | Top threat & mitigation |
|---|---|---|---|---|---|---|---|
| | | | | | | | |

*Then rank the top 5 risks by likelihood × impact.*

---

## 4. Vulnerability Findings  *(25 pts)*

One block per finding (copy as needed):

### Finding F-01 — Forged administrator session token

| Field | Value |
|---|---|
| CWE | CWE-347 — Improper Verification of Cryptographic Signature; CWE-798 — Use of Hard-coded Credentials |
| OWASP 2025 | A07 — Identification and Authentication Failures |
| Severity | Critical |
| Location | `app.py`: hard-coded `SECRET`, `current_user()`, and `/admin` authorization |
| Reproduction | A request without a session and a request using a normal Alice session returned HTTP 403. A locally generated HS256 JWT with `sub=admin`, signed using the exposed development secret, was then sent as the `session` cookie to `GET http://localhost:8080/admin`. The response returned HTTP 200 and administrator records. |
| Impact | An attacker who knows the exposed signing secret can forge an authenticated administrator identity and access administrative functionality. |
| Evidence | `evidence/findings/F-01-forged-session.txt` and `evidence/findings/screenshots/F-01-forged-session.png` |

- The root cause is the hard-coded session-signing secret and insufficiently robust JWT validation. The application also lists `none` among the accepted algorithms. The confirmed working exploit in the installed environment used a forged HS256 token.


### Finding F-02 — SQL injection in login

| Field | Value |
|---|---|
| CWE | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| OWASP 2025 | A03 — Injection |
| Severity | High |
| Location | `app.py`, `/login` route, SQL query construction |
| Reproduction | A normal request using Alice's username and an incorrect password returned HTTP 401. A request using `username=' OR 1=1 -- ` and any password returned HTTP 302, set a session cookie, and redirected to `/`. |
| Impact | An unauthenticated attacker can bypass password authentication and obtain an authenticated application session. |
| Evidence | `evidence/findings/F-02-login-sqli.txt` and `evidence/findings/screenshots/F-02-login-sqli.png` |

- The root cause is direct interpolation of attacker-controlled username data into a SQL statement. Parameterized queries are required so the input remains data rather than SQL syntax.


### Finding F-03 — Privilege escalation through self-registration

| Field | Value |
|---|---|
| CWE | CWE-269 — Improper Privilege Management; CWE-266 — Incorrect Privilege Assignment |
| OWASP 2025 | A01 — Broken Access Control |
| Severity | High |
| Location | `app.py`, `/register` route |
| Reproduction | A normal registration without a role produced a non-administrator account. A second disposable registration submitted `role=admin`, and the new account then accessed `GET http://localhost:8080/admin` with HTTP 200. |
| Impact | An unauthenticated user can create an administrator account and access administrative data. |
| Evidence | `evidence/findings/F-03-role-escalation.txt` and `evidence/findings/screenshots/F-03-role-escalation.png` |

- The root cause is client-controlled assignment of a server-side authorization attribute. Public registration must ignore the submitted role and assign a fixed non-privileged role.


### Finding F-04 — Insecure direct object reference in note retrieval

| Field | Value |
|---|---|
| CWE | CWE-639 — Authorization Bypass Through User-Controlled Key |
| OWASP 2025 | A01 — Broken Access Control; API1:2023 — Broken Object Level Authorization |
| Severity | High |
| Location | `app.py`, `/api/notes/<int:nid>` route |
| Reproduction | Alice successfully reads her own note at `/api/notes/1`. Using the same authenticated session, she changes only the identifier to `/api/notes/2` and receives the administrator-owned note with HTTP 200. An unauthenticated request is rejected with HTTP 401. |
| Impact | Any authenticated user can read another user's note by changing the numeric note ID. |
| Evidence | `evidence/findings/F-04-idor.txt` and `evidence/findings/screenshots/F-04-idor.png` |

- The root cause is that the endpoint checks authentication but does not check ownership. The database query filters only by note ID. The secure query must constrain both the note ID and the authenticated owner.


### Finding F-05 — SQL injection in search

| Field | Value |
|---|---|
| CWE | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command |
| OWASP 2025 | A03 — Injection |
| Severity | High |
| Location | `app.py`, `/search` route |
| Reproduction | Log in as Alice and perform a normal search for `milk`. Then submit the search payload `%' OR owner='admin' -- `. The vulnerable query can be altered so that administrator-owned notes appear in Alice's search results. |
| Impact | An authenticated user can manipulate the search query and potentially read notes outside the user's ownership scope. |
| Evidence | `evidence/findings/F-05-search-sqli.txt` and `evidence/findings/screenshots/F-05-search-sqli.png` |

- The root cause is that both the authenticated username and attacker-controlled search term are interpolated into SQL. The owner and search pattern must be passed as SQL parameters.


### Finding F-06 — Stored cross-site scripting in note rendering

| Field | Value |
|---|---|
| CWE | CWE-79 — Improper Neutralization of Input During Web Page Generation |
| OWASP 2025 | A05 — Injection |
| Severity | High |
| Location | `app.py`, homepage template and `/search` response rendering |
| Reproduction | Log in as Alice and create a note containing `<script>alert(document.domain)</script>`. Visit `http://localhost:8080/`. The stored script executes in the browser when the note is rendered. |
| Impact | An attacker can store script content that executes in another user's browser when the note is viewed. This could enable session abuse or actions in the victim's browser. |
| Evidence | `evidence/findings/F-06-xss.txt`, `evidence/findings/screenshots/F-06-xss-home.png`, and `evidence/findings/screenshots/F-06-xss-alert.png` |

- The root cause is string-built HTML combined with `|safe`, which disables Jinja's normal escaping. User-controlled note values must be passed as structured template data and rendered with contextual escaping.


### Finding F-07 — Command injection in export

| Field | Value |
|---|---|
| CWE | CWE-78 — Improper Neutralization of Special Elements used in an OS Command |
| OWASP 2025 | A03 — Injection |
| Severity | High |
| Location | `app.py`, `/export` route |
| Reproduction | Authenticate as Alice and request `/export?fmt=txt%3Bid`. The vulnerable route passes the attacker-controlled value to `subprocess.run(..., shell=True)`, causing the harmless `id` command to execute and return output. |
| Impact | An authenticated attacker can execute operating-system commands in the application process context. |
| Evidence | `evidence/findings/F-07-command-injection.txt` and `evidence/findings/screenshots/F-07-command-injection.png` |

- The root cause is concatenating attacker-controlled input into a shell command and enabling `shell=True`. The export behavior should be implemented directly in Python or use a strict allowlist with argument-list execution and `shell=False`.

---

## 5. Remediation  *(25 pts)*

Per finding: the fix, **before/after** code, and the commit that implements it.

### Fix for F-01
```diff
- vulnerable line
+ fixed line
```
- **Why this fixes it:** …
- **Commit:** `<hash>`
- **Proof the exploit now fails:** (screenshot)

---

## 6. Supply-Chain Hardening  *(15 pts)*
- **SBOM** (CycloneDX) generated — attach `sbom.json`, note component count.
- **Artifact signed & verified** with Cosign — paste the `cosign verify` output.
- One-paragraph **SLSA** self-assessment (which level, why).

---

## 7. Security CI Pipeline  *(10 pts)*
- Link to the GitHub Actions workflow (SAST + SCA + secret scanning).
- Screenshot of a build **failing** on a HIGH/CRITICAL finding.
- How the gate is configured (what fails the build).

---

## 8. Conclusion & Reflection  *(5 pts — clarity)*
- Residual risks and what you'd harden next.
- Lessons learned.

---

## Appendix
- Tools used, references (OWASP/CWE links), and the team's task split.

---

## Grading rubric (100)

| Criterion | Pts |
|---|---|
| Threat model quality & completeness (§3) | 20 |
| Vulnerability findings — correctness, CWE/OWASP mapping, depth (§4) | 25 |
| Remediation quality — correct, minimal, well-explained (§5) | 25 |
| Supply-chain hardening — SBOM + signing + provenance (§6) | 15 |
| CI pipeline — works, fails build appropriately (§7) | 10 |
| Presentation & report clarity (§1, §8) | 5 |

*All work stays within the [ethics policy](../ETHICS.md).*
