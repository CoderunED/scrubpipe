# ScrubPipe Design Rationale

## Problem

Organizations want to send security logs to cloud analytics and LLM services for enrichment and threat detection, but logs contain sensitive data (PII, credentials, tokens) that cannot leave the organization. Simple masking like `[REDACTED]` solves the privacy problem but destroys the log's analytical value — a SOC analyst can no longer correlate events or hunt threats. Encryption is reversible but non-deterministic by default, so the same value encrypted twice produces different ciphertexts, again breaking correlation.

## Solution: Deterministic Pseudonymization

ScrubPipe implements **deterministic pseudonymization** — replacing sensitive values with consistent, reversible tokens that preserve correlation for analytics while protecting privacy.

### Why deterministic pseudonymization (not masking, not encryption)?

**Masking** (`[REDACTED]`):
- Pro: Simple, irreversible
- Con: Breaks correlation. Same user across 100 events becomes indistinguishable. SOC analysts cannot hunt or correlate.

**Encryption** (standard AES-CBC, etc.):
- Pro: Reversible
- Con: Non-deterministic by default. Same plaintext encrypted twice produces different ciphertexts (due to random IVs). Correlation is broken.

**Deterministic Pseudonymization** (what we use):
- Pro: Reversible + deterministic. Same value always produces the same token. Correlation is preserved.
- Use case: Perfect for log pipelines where you need both privacy and analytical utility.

## Architecture

```
Input Log (JSON)
    ↓
[Analyzer] Find PII
    ├→ Detects: emails, IPs, secrets
    └→ Returns: entity type, value, position
    ↓
[Tokenizer] HMAC-based replacement
    ├→ HMAC(secret_key, value) → deterministic token
    ├→ Replace original value with token
    └→ Preserve position/structure
    ↓
[Vault] Store reversible mapping (Phase 4+)
    ├→ Maps: TOKEN_a3f9 ↔ alice@example.com
    ├→ Locked behind secret key
    └→ Audited access for re-identification
    ↓
Output Log (JSON with tokens)
```

## How It Works

### Step 1: Detection (Presidio Analyzer)

The Analyzer scans each log field for known PII patterns:

```
Input: user_email = "alice@example.com"
Analyzer output: EMAIL_ADDRESS found at position [0:20]
```

### Step 2: Tokenization (HMAC-based)

For each detected value, we create a deterministic token:

```python
token = HMAC-SHA256(secret_key, "alice@example.com")[:8]
       = "EMAIL_a3f9"
```

**Key property: Same key + same value = same token, every time.**

### Step 3: Replacement

Replace the original value with the token:

```
Before: user_email = "alice@example.com"
After:  user_email = "EMAIL_a3f9"
```

### Step 4: Correlation Preserved

When the same email appears in multiple events:

```
Event 1: user_email = "EMAIL_a3f9", action = "login"
Event 2: user_email = "EMAIL_a3f9", action = "file_access"
Event 3: user_email = "EMAIL_a3f9", action = "logout"
```

A SOC analyst sees the **same token in all three events** and immediately knows these actions are from the same user. Correlation works.

### Step 5: Reversibility (Vault, Phase 4+)

The vault stores the mapping:

```
EMAIL_a3f9 ↔ alice@example.com
```

When an incident responder needs to investigate:

1. They see suspicious activity from `EMAIL_a3f9`
2. They query the vault (with proper authorization)
3. Vault returns: alice@example.com
4. They can now block the account, open a ticket, etc.
5. All access is audited: who re-identified, when, why

## Why This Matters

### For Privacy
- Logs sent to cloud services contain tokens, not real values
- Original PII never leaves the organization (stays in vault)
- Complies with data minimization principles

### For SOC Capability
- Unlike masking, analysts can still correlate across events
- Can hunt: "show me all actions by EMAIL_a3f9"
- Can pivot: "which IP did EMAIL_a3f9 use most often?"
- Can respond: re-identify when legally authorized

### For Compliance
- Pseudonymization is recognized by GDPR, HIPAA, SOC 2
- Reversibility under policy is a key feature regulators respect
- Audit trail proves who re-identified and when

## Technical Choices

### HMAC-SHA256
- Deterministic: HMAC(key, x) always produces the same output for the same inputs
- One-way: Cannot reverse the token back to the original without storing the mapping separately
- Proven secure: Resistant to length-extension attacks that plague simpler MAC constructions
- Fast: Efficient even at high log volumes

### Token Truncation (8 characters)
- v0 uses 8-character display tokens for human readability
- Production should consider NIST SP 800-107 recommendation of ≥128 bits for collision resistance
- Can maintain separate internal (full-length) and display (truncated) tokens

### Secret Key
- The secret key must be protected like any cryptographic key
- Different keys → different tokens (even for the same original value)
- Key rotation strategy needed for production (future work)

## Known Limitations (v0)

1. **Token collision risk**: 8-character truncation creates a collision risk at very high log volumes. Future versions should use full 128-bit internal tokens.

2. **No domain separation**: Currently all field types (emails, IPs, etc.) use the same key. Future versions should domain-separate: `HMAC(key, "email" || value)` vs `HMAC(key, "ip" || value)`.

3. **Key rotation complexity**: Deterministic tokenization is tied to the key. If the key rotates, historical tokens won't match new tokens for the same value, breaking correlation across the rotation boundary. Future versions need a rotation strategy.

4. **Vault access control**: v0 does not implement access control on the vault. Production needs role-based access, audit logging, and encryption of the vault itself.

5. **No compression of tokens**: Current design stores one token per unique value. Could optimize with a reverse index for massive log volumes.

## Future Enhancements (Roadmap)

- [ ] Implement access-controlled vault with encryption
- [ ] Add domain separation by field type
- [ ] Support key rotation with historical key mapping
- [ ] Audit logging for all re-identification events
- [ ] Implement full 128-bit internal token representation
- [ ] Add native Vector/OTel processor plugins
- [ ] Performance optimization for >10k events/sec throughput

## References

- OWASP Data Anonymization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Data_Anonymization_Cheat_Sheet.html
- Python HMAC documentation: https://docs.python.org/3/library/hmac.html
- Microsoft Presidio Anonymizer: https://microsoft.github.io/presidio/anonymizer/
- NIST SP 800-107 (MAC guidance): Recommendation for Information Security
