# Nymstr Groupd Protocol

This document specifies the JSON‑based message protocol over the Nym mixnet between
clients and the group server (`nymstr-groupd`). Each message is a JSON object with an
`action` field; the server replies with a corresponding `*Response` action.

---

## 1. Registration (Join Request)

Clients register their username and PGP public key and request approval.

**Request** (`action = "register"`):
```json
{
  "action": "register",
  "username": "<user_name>",
  "publicKey": "<ASCII-armored PGP public key>",
  "signature": "<detached signature over publicKey>"
}
```
【F:src/message_utils.rs†L108-L140】

**Response** (`action = "registerResponse"`):
- `content = "pending"` (join request recorded)
- `content = "error: user already registered"` (duplicate)
- `content = "error: registration failed"` (DB or validation error)
【F:src/message_utils.rs†L141-L165】

---

## 2. Approve Membership (Admin Only)

An admin (configured via env vars) approves a pending user.

**Request** (`action = "approveGroup"`):
```json
{
  "action": "approveGroup",
  "username": "<user_name>",
  "signature": "<detached signature over username>"
}
```
【F:src/message_utils.rs†L170-L226】

**Response** (`action = "approveGroupResponse"`):
- `content = "success"`
- `content = "error: unauthorized or bad signature"`
- `content = "error: approve failed"`
【F:src/message_utils.rs†L227-L268】

---

## 3. Connect (After Approval)

Approved users prove control of their username before joining.

**Request** (`action = "connect"`):
```json
{
  "action": "connect",
  "username": "<user_name>",
  "signature": "<detached signature over username>"
}
```
【F:src/message_utils.rs†L228-L260】

**Response** (`action = "connectResponse"`):
- `content = "success"`
- `content = "error: user not registered or not approved"`
- `content = "error: bad signature"`
【F:src/message_utils.rs†L247-L270】

---

## 4. Send Group Message

Connected users send encrypted messages to the group’s Redis stream.

**Request** (`action = "sendGroup"`):
```json
{
  "action": "sendGroup",
  "ciphertext": "<base64-or-hex ciphertext>"
}
```
【F:src/message_utils.rs†L272-L284】【F:src/message_utils.rs†L302-L314】

**Response** (`action = "sendGroupResponse"`):
- `content = "success"`
- `content = "error: missing ciphertext"`
【F:src/message_utils.rs†L315-L317】

---

## 5. Fetch New Messages

Clients pull new messages from the Redis stream since a last‑seen ID.

**Request** (`action = "fetchGroup"`):
```json
{
  "action": "fetchGroup",
  "lastSeenId": "<stream_entry_id>",
  "signature": "<detached signature over lastSeenId>"
}
```
【F:src/message_utils.rs†L320-L336】

**Response** (`action = "fetchGroupResponse"`):
```json
{
  "action": "fetchGroupResponse",
  "messages": [ ["<ciphertext>", "<messageId>"], … ]
}
```
【F:src/message_utils.rs†L351-L357】

---

## Security Notes

- All requests must include a detached PGP `signature` over the request payload.
- The server verifies each signature against the registered publicKey (or ADMIN_PK for admin calls).
- All responses are similarly PGP‑signed via `send_encapsulated_reply`.
【F:src/message_utils.rs†L667-L701】

_Generated from server code in `src/message_utils.rs`._