# Business Architecture Report — Anti-Hack

> **Part of the SATechnologies portfolio architecture review.**
> Portfolio index, shared-DNA analysis and cross-project synthesis: [`../ARCHITECTURE-PORTFOLIO.md`](../ARCHITECTURE-PORTFOLIO.md)
>
> **Lens:** business domain · core modules · domain model · business workflows · reusable capabilities · infrastructure · configuration · hardcoded rules · candidate engines · architecture · technical debt · product opportunities · business rules.
> **Out of scope:** framework mechanics, code style, refactoring advice.

---

# PROJECT 11 — Anti-Hack (`anti_hack_project`)

*An account-security prototype: password strength, two-factor flag, and an audit trail of security events. The smallest project in the portfolio, and the most useful as a reference implementation of an **audit-first security model**.*


## 1. The Business Domain

**Problem solved.** Users do not know whether their account is secure, and when something changes they do not know what happened. Anti-Hack gives a user a **security posture view** (password strength, 2FA status, recent activity) backed by a **security log** recording every security-relevant action.

**The domain insight.** Account security is fundamentally an **observability problem before it is a prevention problem**. Most products only prevent (password rules, rate limits). Anti-Hack also *explains*: it tells the user what state their account is in, and it records what changed so that "something looks wrong" becomes answerable.

**The commercial reading.** As a standalone product this has no market. As a **module**, it is the security panel every product in this portfolio should have — and it is deliberately written as a small, self-contained reference implementation.

## 2. Core Modules

| Module | Business purpose |
|---|---|
| **User Accounts** | The subject of the security posture. |
| **Password Strength Assessment** | Score a password's strength and explain what is weak about it. |
| **Password Management** | Set/change a password with a history of changes. |
| **Two-Factor Flag** | Whether 2FA is enabled (a flag in this prototype; the pattern for a real TOTP flow). |
| **Security Log** | An append-only record of security events: login, password change, 2FA toggle, failed attempts. |
| **Security Score** | A derived score from password strength + 2FA + recent activity. |
| **Recommendations** | Actionable advice derived from the score's components. |
| **Activity View** | The user-facing timeline of their own security events. |

## 3. Domain Model

```
User ──> id, email, password_hash, two_factor_enabled (bool), created_at
   └──1:N──> SecurityLog

SecurityLog ──> id, user_id, event_type, detail, ip_address, user_agent, created_at
   └── event_type: account_created | login_success | login_failed |
                    password_changed | two_factor_enabled | two_factor_disabled |
                    suspicious_activity

SecurityProfile (derived, not stored) ──> score, components[], recommendations[]
```

**Key modelling decision:** `SecurityLog` is **append-only and separate from the user record**. The user can change their password, but the history of every change persists. This separation is the point of the model.

**The security score is derived, not stored** — it is computed from current state (password strength, 2FA, recent failures) so it cannot drift out of sync with reality.

## 4. Business Workflows

### W1 — Account creation
```
User registers (email, password)
  → Password assessed for strength
  → Password stored hashed (never plaintext)
  → SecurityLog: account_created
  → 2FA defaults to disabled → a recommendation is generated
```

### W2 — Login
```
Login attempt
  → Credentials verified against the hash
  → Success: SecurityLog (login_success, IP, user agent)
            Failure: SecurityLog (login_failed, IP, user agent)
  → Repeated failures surface in the security view as a warning and
    contribute to the score (recent failures lower it)
```

### W3 — Password change
```
User supplies current + new password
  → Current verified → new assessed for strength
  → If weak, refused (with the assessment as the reason)
  → New password hashed and stored; previous hash discarded
  → SecurityLog: password_changed (no password material logged, ever)
  → Score recomputed
```

### W4 — Two-factor toggle
```
User enables 2FA
  → flag set → SecurityLog: two_factor_enabled
  → Score increases (2FA is a positive component)
User disables 2FA
  → flag cleared → SecurityLog: two_factor_disabled
  → Score decreases, and a recommendation reappears
```

### W5 — Security review
```
User opens their security view
  → Score computed from components:
        password strength (weak/moderate/strong)
        2FA enabled (yes/no)
        recent failed logins (count/recency)
  → Timeline of the user's SecurityLog entries shown newest-first
  → Recommendations generated from the weak components
     (e.g. "Enable two-factor authentication", "Your password is weak",
      "There were 3 failed logins in the last hour")
```

## 5. Reusable Business Capabilities

| Capability | Reusability |
|---|---|
| **Append-only security/audit log with event taxonomy** | ★★★★★ |
| **Derived security score with explainable components** | ★★★★★ |
| **Password strength assessment that explains, not just scores** | ★★★★☆ |
| **Security event taxonomy (login/password/2FA/suspicious)** | ★★★★★ |
| **Failed-login tracking feeding a risk signal** | ★★★★☆ |
| **2FA as a first-class security state** | ★★★☆☆ (flag only in this prototype) |
| **User-facing "what happened to my account" timeline** | ★★★★★ |

## 6. Infrastructure Components

| Component | Role |
|---|---|
| **Web application runtime** | Serving the app. |
| **Relational database** | Users, security logs. |
| **Password hashing** | Secure hash function. |
| **IP / user-agent capture** | Request context for the log. |
| **No external services** | No mail, no SMS, no TOTP provider. |

## 7. Configuration Points

- Password strength thresholds (score bands and minimums)
- Recent-failure window and count that lowers the score
- 2FA weighting in the score
- Event types retained vs purged (log retention window)
- Score bands and their labels

## 8. Hardcoded Business Rules

| Rule | Consequence |
|---|---|
| **2FA is a boolean, not a real second factor** | The flag models the *state* without implementing TOTP. Acceptable for a prototype, dangerous if mistaken for a real 2FA. |
| **No rate limiting or lockout on login** | A security product with an unthrottled login is self-defeating. |
| **No session/cookie security modelled** | Session fixation and hijack are out of scope. |
| **No notification on suspicious activity** | A log nobody is told about is a log nobody reads. |
| **Password change does not invalidate other sessions** | A stolen session survives a password reset. |
| **Security log has no integrity protection** | A compromised app can erase its own history. |
| **No breach/credential-stuffing intelligence** | Scoring is self-contained, not informed by external exposure. |
| **No admin view of security logs** | Users can only see their own; operators cannot spot a pattern across users. |
| **No recovery/reset flow modelled** | The most common account-security event is absent. |

## 9. Candidate Engines

### E1 — Security Event Ledger
**Purpose:** Maintain an append-only, tamper-evident record of every security-relevant event.
**Responsibilities:** Event capture (type, actor, IP, user agent, timestamp), taxonomy enforcement, retention, integrity (hash chaining / signing), querying, alerting hooks.
**Inputs:** Security event, request context.
**Outputs:** Immutable log entries, integrity verification, alerts.
**Possible API:**
```
POST /internal/security-events   {user_id, type, detail}
GET  /security/events?user_id=&from=&to=
GET  /security/events/verify    (integrity check)
```
**Possible Events:** `security.event_recorded`, `security.integrity_violation`, `security.repeated_failures`, `security.suspicious_activity`

### E2 — Password Strength & Policy Engine
**Purpose:** Assess and enforce password quality, explaining the reason rather than just rejecting.
**Responsibilities:** Strength scoring (length, variety, commonality, breach-list check), minimum policy enforcement, explanation, guidance, password history to prevent reuse.
**Inputs:** Password (assessed, never stored).
**Outputs:** Score, band, reasons, guidance, accept/reject.
**Possible API:**
```
POST /security/password/assess  {password} -> {score, band, reasons, suggestions}
POST /security/password/policy  {min_length, ...}
```
**Possible Events:** `password.weak_detected`, `password.reused`, `password.policy_violated`

### E3 — Account Security Posture Engine
**Purpose:** Compute an explainable security score for an account and turn its weak components into actions.
**Responsibilities:** Component aggregation (password, 2FA, recent failures, session hygiene), weighting, banding, recommendation generation, score change notification.
**Inputs:** User security state, recent events.
**Outputs:** Score, components, recommendations, trend.
**Possible API:**
```
GET  /security/posture?user_id=
POST /security/posture/notify   (send the user their score/recommendations)
```
**Possible Events:** `posture.computed`, `posture.degraded`, `posture.improved`, `recommendation.actioned`

### E4 — Anomaly Detection (over patterns)
**Purpose:** Spot suspicious patterns (impossible travel, burst failures, new-device logins) rather than just recording events.
**Responsibilities:** Baseline per user, pattern rules, alerting, investigation context, false-positive handling.
**Inputs:** Security events, baselines.
**Outputs:** Alerts, risk flags.
**Possible API:**
```
GET  /security/anomalies?user_id=
POST /security/anomalies/:id/ack
```
**Possible Events:** `anomaly.detected`, `anomaly.acknowledged`, `anomaly.escalated`

## 10. Overall Architecture Diagram

```
                    USER (browser)
                         │
                         ▼
   ┌─────────────────────────────────────────┐
   │  Security views                        │
   │  · Security score + components         │
   │  · Recommendations                     │
   │  · Activity timeline (own events)      │
   │  · Change password / toggle 2FA        │
   └───────────────────┬─────────────────────┘
                       │
                       ▼
   ┌─────────────────────────────────────────┐
   │  Security layer                         │
   │  E1 Security Event Ledger (append-only)│
   │  E2 Password Strength & Policy         │
   │  E3 Account Security Posture           │
   │  E4 Anomaly Detection (over patterns)  │
   └───────────────────┬─────────────────────┘
                       │  (every action emits an event)
                       ▼
   ┌─────────────────────────────────────────┐
   │  Database                               │
   │  users (email, password_hash,           │
   │         two_factor_enabled)             │
   │  security_logs (user_id, event_type,    │
   │   detail, ip_address, user_agent, ts)  │
   └─────────────────────────────────────────┘
```

## 11. Technical Debt

| Debt | Severity | Note |
|---|---|---|
| **2FA is a flag, not a factor** | **Critical** | The state is modelled but nothing is actually verified. Must not be described as 2FA. |
| **No login rate limiting / lockout** | **Critical** | A security product that doesn't throttle is not a security product. |
| **No notification on suspicious activity** | High | Logs nobody is alerted to don't protect anyone. |
| **Password change doesn't invalidate sessions** | High | A reset that leaves stolen sessions alive is half a fix. |
| **Security log is not tamper-evident** | High | No hash chaining or signing. |
| **No admin/cross-user security view** | Medium | Patterns across users are invisible. |
| **No recovery/reset flow** | Medium | The most common account-security event is unmodelled. |
| **No session hygiene** | Medium | Cookie flags, idle timeout, device list unmodelled. |
| **No test suite** | High | |

## 12. Product Opportunities

| Module | Becomes |
|---|---|
| **E1 Security Event Ledger** | *"Auditable account security"* — a panel for any SaaS that must answer "who changed what, when, from where". |
| **E3 Posture Engine** | *"Security score for end users"* — consumer-facing, explainable, and a real differentiator for fintech-adjacent products. |
| **E4 Anomaly Detection** | *"Account takeover detection"* — the natural next layer above a log. |
| **The project itself** | The reference implementation of an audit-first security model for the rest of the portfolio. |

## 13. Business Rules

### Accounts
- A user has an email, a hashed password, and a 2FA flag.
- Passwords are stored **hashed only**; no plaintext is ever persisted or logged.

### Security Events
- Every security-relevant action writes an **append-only** `SecurityLog` entry.
- Each entry records: user, event type, detail, **IP address, user agent, timestamp**.
- Event types: `account_created`, `login_success`, `login_failed`, `password_changed`, `two_factor_enabled`, `two_factor_disabled`, `suspicious_activity`.
- Log entries are never modified; a change to a password does not erase the record of the previous one.
- A user can view only their own log.

### Passwords
- A password is assessed for strength before it is accepted.
- A password that fails policy is **refused**, and the assessment reasons are shown.
- Changing a password requires verifying the current one.
- Previous password hashes are discarded; password history prevents immediate reuse.

### Two-Factor
- 2FA is a boolean state on the account, defaulting to disabled.
- Toggling it on or off writes a log entry in both directions.
- A disabled 2FA state always produces a recommendation.

### Security Posture (score)
- The score is **derived from current state**, never stored, so it cannot drift.
- Components: password strength, 2FA enabled, recent failed logins (count and recency).
- Each component contributes to the score; the components and their weights are visible to the user.
- A degraded component produces a specific recommendation (e.g. "Enable 2FA", "Your password is weak", "3 failed logins recently").
- A drop in score is a notable event; an improvement is worth acknowledging.

## 13b. Notable Business Design Decisions

1. **Observability before prevention.** The product's core value is explaining and recording account state — prevention (hashes, policy) is assumed.
2. **Derived, not stored, security score.** Computing the posture on read guarantees it reflects reality, at the cost of recomputation.
3. **The log is separate from the user record.** That separation is the whole audit model: mutable account state, immutable history.
4. **Recommendations are derived from components, not hardcoded.** The advice follows the state, so it never contradicts the score.
5. **Honest about its limits.** 2FA is a flag, not a factor; login is unthrottled. Recognising this is what makes it a safe reference implementation — the moment it is mistaken for a real security product, its gaps become liabilities.


