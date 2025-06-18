# nymstr-groupd

 `nymstr-groupd` is a group chat server built on the Nym mixnet, providing privacy-preserving group messaging. It handles group creation and management, encrypted messaging, and real-time delivery over mixnet and Redis.

## Features

- **Anonymous Messaging**: Clients connect to the Nym mixnet for privacy-preserving message transport.
- **Group Management**: Create public/private groups, join public groups, invite and approve members for private groups.
- **Encrypted & Signed Messages**: End-to-end encrypted and signed messages ensure confidentiality and integrity.
- **Persistent Metadata**: SQLite database for users, groups, memberships, and invites.
- **Real-time Delivery**: Redis Pub/Sub to broadcast messages to group members.
- **Configurable Storage & Logging**: Easy environment-based configuration for logs, database, keys, and Nym SDK storage.

## Prerequisites

- Rust toolchain (Rust 1.70+)
- SQLite
- Redis server
- OpenSSL (for cryptographic operations)

## Installation

```bash
git clone https://github.com/your_org/nymstr-groupd.git
cd nymstr-groupd
cargo build --release
```

## Configuration

Configure the server via environment variables or by creating a `.env` file in the project root. The following variables are supported:

| Variable         | Default                         | Description                                        |
|------------------|---------------------------------|----------------------------------------------------|
| `LOG_FILE_PATH`  | `logs/groupd.log`               | Path to the log file (directories will be created) |
| `DATABASE_PATH`  | `storage/groupd.db`             | Path to the SQLite database                        |
| `KEYS_DIR`       | `storage/keys`                  | Directory for storing encrypted key pairs          |
| `SECRET_PATH`    | `secrets/encryption_password`   | File containing the encryption password            |
| `NYM_CLIENT_ID`  | `groupd`                        | Nym mixnet client identifier                       |
| `NYM_SDK_STORAGE`| `storage/<NYM_CLIENT_ID>`       | Directory for Nym SDK storage                      |
| `REDIS_URL`      | `redis://127.0.0.1/`            | Redis connection URL                               |

Example `.env`:
```dotenv
LOG_FILE_PATH=logs/groupd.log
DATABASE_PATH=storage/groupd.db
KEYS_DIR=storage/keys
SECRET_PATH=secrets/encryption_password
NYM_CLIENT_ID=groupd
NYM_SDK_STORAGE=storage/groupd
REDIS_URL=redis://127.0.0.1/
```

Before starting, initialize the encryption password file:
```bash
mkdir -p "$(dirname "${SECRET_PATH:-secrets/encryption_password}")"
echo "YOUR_ENCRYPTION_PASSWORD" > "${SECRET_PATH:-secrets/encryption_password}"
```

## Running the Server

```bash
cargo run --release
```

The server will:
- Load environment variables (.env)
- Initialize logging to console and file
- Set up SQLite database and tables
- Prepare cryptographic key storage
- Connect to the Nym mixnet using `nym-sdk`
- Subscribe to Redis channels for group pub/sub
- Listen for incoming JSON commands over the mixnet

## API: JSON Actions

Clients communicate with the server by sending JSON messages over the Nym mixnet. Each message must include an `"action"` field. Below are the supported actions:

### `connect`
Subscribe to group channels for message delivery.
```json
{ "action": "connect" }
```

### `createGroup`
Create a new group.
```json
{
  "action": "createGroup",
  "groupName": "My Group",
  "isPublic": true,
  "isDiscoverable": false
}
```
Response: `createGroupResponse` with `groupId`.

### `joinGroup`
Join a public group.
```json
{
  "action": "joinGroup",
  "groupId": "<UUID>"
}
```
Response: `joinGroupResponse` with status.

### `inviteGroup`
Invite a user to a private group (admin only).
```json
{
  "action": "inviteGroup",
  "groupId": "<UUID>",
  "username": "alice"
}
```
Response: `inviteGroupResponse` with status.

### `approveGroup`
Approve an invited user to join (admin only).
```json
{
  "action": "approveGroup",
  "groupId": "<UUID>",
  "username": "alice"
}
```
Response: `approveGroupResponse` with status.

### `sendGroup`
Send an encrypted message to group members.
```json
{
  "action": "sendGroup",
  "groupId": "<UUID>",
  "ciphertext": "<encrypted_payload>"
}
```
Response: `sendGroupResponse` with status.

## Logging

Logging is provided by [`fern`] with colored output in the console and timestamped entries in the log file (see `LOG_FILE_PATH`).

## Persistence

Database schema is defined in `src/db_utils.rs`, with tables for `users`, `groups`, `group_members`, and `group_invites`.
