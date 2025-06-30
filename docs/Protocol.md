# Nymstr Groupd Protocol

This document specifies the JSON‐based message protocol over the Nym mixnet between
clients and the group server (`nymstr-groupd`).  Each request is a JSON object with an
`action` field; the server replies with a corresponding `*Response` action.

---

## 1. Registration

Clients register their PGP public key under a chosen username before any other actions.

**Request** (`action = "register"`):
```json
{
  "action": "register",
  "username": "<user_uuid>",
  "publicKey": "<ASCII-armored PGP public key>"
}
```
【F:src/message_utils.rs†L366-L387】

**Response** (`action = "registerResponse"`):
- Success: `content = "success"`
- Already registered: `content = "error: user already registered"`
- Failure: `content = "error: registration failed"`
【F:src/message_utils.rs†L420-L443】

---

## 2. Connect

Clients signal they are online by signing their registered public key.

**Request** (`action = "connect"`):
```json
{
  "action": "connect",
  "username": "<user_uuid>",
  "publicKey": "<ASCII-armored PGP public key>",
  "signature": "<ASCII-armored detached PGP signature>"
}
```
【F:src/message_utils.rs†L446-L477】【F:examples/client.rs†L133-L151】

**Response** (`action = "connectResponse"`):
- Success: `content = "success"`
- Missing fields or mismatch: `content = "error: ..."`
【F:src/message_utils.rs†L478-L538】

---

## 3. Send Group Message

Clients send encrypted group messages as opaque ciphertext to the single group.

**Request** (`action = "sendGroup"`):
```json
{
  "action": "sendGroup",
  "ciphertext": "<base64-or-hex ciphertext>"
}
```
【F:src/message_utils.rs†L272-L284】【F:src/message_utils.rs†L302-L314】

**Response** (`action = "sendGroupResponse"`):
- Success: `content = "success"`
- Error: `content = "error: ..."`
【F:src/message_utils.rs†L315-L317】

---

## 4. Fetch New Messages

Clients fetch new group messages since their last seen entry ID. The server
does not require a groupId since there's only one group.

**Request** (`action = "fetchGroup"`):
```json
{
  "action": "fetchGroup",
  "lastSeenId": "<stream_entry_id>"
}
```
【F:src/message_utils.rs†L320-L326】【F:src/message_utils.rs†L330-L336】

**Response** (`action = "fetchGroupResponse"`):
```json
{
  "action": "fetchGroupResponse",
  "messages": [ ["<ciphertext>", "<messageId>"], ... ]
}
```
【F:src/message_utils.rs†L351-L357】

Clients send encrypted group messages as opaque ciphertext.

**Request** (`action = "sendGroup"`):
```json
{
  "action": "sendGroup",
  "groupId": "<group_uuid>",
  "ciphertext": "<base64-or-hex ciphertext>"
}
```
【F:src/message_utils.rs†L567-L618】

**Response** (`action = "sendGroupResponse"`):
- (no direct response; errors via mixing back `sendGroupResponse` with error content)
【F:src/message_utils.rs†L567-L618】

---

## 8. Fetch New Messages

Clients fetch new group messages since their last seen ID.

**Request** (`action = "fetchGroup"`):
```json
{
  "action": "fetchGroup",
  "groupId": "<group_uuid>",
  "lastSeenId": "<stream_entry_id>"
}
```
【F:src/message_utils.rs†L446-L477】【F:src/message_utils.rs†L567-L618】

**Response** (`action = "fetchGroupResponse"`):
```json
{
  "action": "fetchGroupResponse",
  "groupId": "<group_uuid>",
  "messages": [ ["<ciphertext>", "<messageId>"], ... ]
}
```
【F:src/message_utils.rs†L538-L584】

---

## Security Notes

- All responses from the server carry a detached PGP signature over the `content` field using the server’s private key:
  handled in `send_encapsulated_reply`【F:src/message_utils.rs†L667-L701】.
- Clients **must** verify the `signature` in the server’s JSON responses before trusting `content`.

---

_Generated from server code definitions in `src/message_utils.rs`._