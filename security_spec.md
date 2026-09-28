# NEXSUSv3 Firestore Security Specification

## 1. Data Invariants
1. **Default Deny**: All paths not explicitly matched are denied by `match /{document=**} { allow read, write: if false; }`.
2. **Verified Identity**: All writes require `request.auth != null && request.auth.token.email_verified == true`.
3. **PII Isolation**: User email is stored only in `/users/{userId}/private/{docId}` and is readable only by the owner (`request.auth.uid == userId`) or a verified Admin (`isAdmin()`).
4. **Role Integrity**: Self-assigned admin privilege escalation is blocked on `/users/{userId}` creation (`data.role in ['Analyst', 'Viewer'] || isAdmin()`). Users cannot modify their own `role` field on update unless `isAdmin()`.
5. **Query Enforcer**: All `allow list` rules evaluate `resource.data.ownerId == request.auth.uid || isAdmin()` without performing `get()` or `exists()` calls inside list rules.
6. **Immutable Audit Logs**: `/audit_logs/{logId}` allows `create` by verified users where `actorId == request.auth.uid`, and strictly forbids `update` and `delete`.

## 2. The "Dirty Dozen" Payloads
1. **Shadow Field Injection on Investigation**: `{ "id": "inv-1", ..., "isSuperAdmin": true }` -> Rejected by `.keys().hasOnly(...)`.
2. **Self-Assigned Admin Role on User Profile**: `{ "uid": "u1", "name": "Attacker", "role": "Admin", ... }` -> Rejected for non-admin user.
3. **Unverified Email Spoof**: Request with `auth.token.email == "friends20052005@gmail.com"` and `email_verified == false` -> Rejected by `isVerifiedUser()`.
4. **Cross-User PII Read**: Authenticated user `u2` attempting `get(/users/u1/private/info)` -> Rejected by `request.auth.uid == userId || isAdmin()`.
5. **Owner Spoofing on Sample Upload**: `{ "id": "s1", "ownerId": "other-uid", ... }` -> Rejected by `data.ownerId == request.auth.uid`.
6. **Oversized Document ID Poisoning**: Document ID of 512 bytes or containing special characters -> Rejected by `isValidId()`.
7. **Value Poisoning on Investigation Update**: Updating `status` to a number or invalid enum -> Rejected by `isValidInvestigation(incoming())`.
8. **Terminal State Mutation**: Attempting to update an investigation whose `existing().status == 'COMPLETED'` as a non-admin -> Rejected by terminal state lock.
9. **Audit Log Tampering (Update)**: Attempting `update` on `/audit_logs/log-1` -> Rejected (`allow update, delete: if false`).
10. **Audit Log Deletion**: Attempting `delete` on `/audit_logs/log-1` -> Rejected (`allow update, delete: if false`).
11. **Immutable Owner Mutation**: Attempting to change `ownerId` or `createdAt` during an update on `/investigations/{id}` -> Rejected by `incoming().ownerId == existing().ownerId`.
12. **Blanket Unfiltered List Query**: Attempting `list` on `/investigations` without `where('ownerId', '==', uid)` as a non-admin -> Rejected by `resource.data.ownerId == request.auth.uid`.
