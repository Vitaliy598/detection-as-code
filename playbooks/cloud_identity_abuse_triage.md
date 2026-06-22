# Cloud Identity Abuse Triage Playbook

## Goal

Investigate suspicious cloud identity activity involving MFA abuse, unusual login, external inbox forwarding, mailbox access, and active suspicious sessions.

## Required evidence

1. Alert summary
   - Alert ID
   - User
   - Source IP
   - Severity
   - Signals

2. Raw identity events
   - Failed login
   - MFA denied
   - MFA approved
   - Successful login
   - Country and Source IP

3. User baseline
   - Known country
   - Known source IP
   - Known device
   - MFA expected

4. Inbox rule evidence
   - Rule ID
   - Created time
   - Created by IP
   - ForwardTo address
   - Enabled status
   - Action type

5. Mailbox activity
   - Mail read
   - Mail search
   - Attachment download
   - Search terms or accessed folders

6. Active sessions
   - Session ID
   - Source IP
   - Country
   - Last seen
   - Status

## Verdict logic

Confirmed compromise is supported when the following are visible:

- MFA denied then approved from the suspicious source
- Successful login from unusual country or IP
- External inbox forwarding rule created
- Mailbox read/search/download activity observed
- Suspicious session is still active

## Immediate containment

P1 actions:

- Revoke active sessions
- Reset user password
- Revoke refresh tokens
- Remove external inbox rule

P2 actions:

- Block source IP
- Review mailbox access
- Require MFA re-registration
- Notify user and management

## Reporting structure

Separate the report into:

- What is visible
- What can be inferred
- What is missing
- Verdict
- Immediate actions
- Follow-up actions
