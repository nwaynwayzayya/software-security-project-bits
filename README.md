# NoteVault — Term-Project Starter Target

A small team note-sharing web app + JSON API. **This is the default target for your
[term project](../README.md).** It looks like a normal app and works end-to-end —
but it was built quickly, without a security review. Your job is to fix that.

> ⚠️ Sandbox only. Run it locally; never deploy this as-is. See [ETHICS.md](../../ETHICS.md).

## What it does
- Register / log in (cookie session)
- Create and view your own notes
- Search your notes
- Admin panel listing users
- "Export" convenience endpoint

## Run it locally
```bash
export TEAM_ID=<your-team-name>
export NOTEVAULT_SECRET=<local-development-secret>
export SESSION_COOKIE_SECURE=0
docker compose up --build
# open http://localhost:8080
```

`NOTEVAULT_SECRET` is required at runtime and must not be committed. Set
`SESSION_COOKIE_SECURE=1` when serving the application over HTTPS. The seeded
accounts are for the authorized local sandbox only.

> **Set `TEAM_ID` before your first build.** It seeds a small marker derived from your team
> name into the app's own data — the same idea as the per-student flags in the weekly labs,
> just per-team here since every team starts from the same codebase. It doesn't change any
> app behavior or interfere with your assignment; it exists purely so your submitted
> evidence (screenshots, dumped data, git history) is provably yours if two reports look
> unusually similar.

## Your assignment (maps to the rubric in [../REPORT-TEMPLATE.md](../REPORT-TEMPLATE.md))
1. **Threat-model** NoteVault — DFD + STRIDE, trust boundaries, top risks. *(Week 1)*
2. **Find & document vulnerabilities** — there are several, spanning the course
   (input handling, access control, sessions, crypto, dependencies, container/config).
   For each: CWE + OWASP mapping, reproduction, impact, evidence. *(Weeks 3–6, 10, 12–13)*
3. **Remediate** — fix each finding in a branch with clear commits. *(all term)*
4. **Supply-chain hardening** — SBOM (CycloneDX) + sign the image with Cosign. *(Week 12)*
5. **Harden the build** — fix the `Dockerfile`; add a **security CI pipeline**
   (SAST + SCA + secret scanning) that fails on HIGH/CRITICAL. *(Weeks 13, 15)*
6. **Demo** — attack → root cause → fix (Week 19).

## Suggested attack surface to probe
The login, register, note, search, admin, and export endpoints; the session
cookie; `requirements.txt`; and the `Dockerfile`. Use the techniques and tools
from the weekly labs (Burp, sqlmap, Trivy, Semgrep, Gitleaks, Cosign).

> Teams may propose their own app instead, with instructor approval — but it must
> offer comparable depth across the same categories.
