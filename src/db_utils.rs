use anyhow::Result;
use sqlx::{Row, SqlitePool};
use std::path::Path;

#[derive(Clone)]
pub struct DbUtils {
    pool: SqlitePool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[tokio::test]
    async fn test_user_pending_and_group_flows() -> Result<()> {
        let db = DbUtils::new(":memory:").await?;
        // Test add/get user
        assert!(db.add_user("alice", "pk1").await?);
        assert!(!db.add_user("alice", "pk1").await?);
        let u = db.get_user_by_username("alice").await?;
        assert_eq!(u, Some(("alice".to_string(), "pk1".to_string())));

        // Test pending users
        assert!(db.add_pending_user("bob", "pk2").await?);
        assert!(!db.add_pending_user("bob", "pk2").await?);
        let p = db.get_pending_user("bob").await?;
        assert_eq!(p, Some("pk2".to_string()));
        assert!(db.remove_pending_user("bob").await?);

        // Test group flows
        assert!(
            db.create_group("g1", "Group1", "alice", true, false)
                .await?
        );
        assert!(db.is_group_public("g1").await?);
        assert!(db.add_group_member("g1", "alice").await?);
        let members = db.get_group_members("g1").await?;
        assert_eq!(members, vec!["alice".to_string()]);
        assert!(db.is_user_admin("g1", "alice").await?);
        let groups = db.get_groups_for_user("alice").await?;
        assert_eq!(groups, vec!["g1".to_string()]);
        Ok(())
    }
}

#[allow(dead_code)]
impl DbUtils {
    /// Open or create the SQLite database at the specified path.
    pub async fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_url = format!("sqlite://{}", db_path.as_ref().display());
        let pool = SqlitePool::connect(&db_url).await?;
        sqlx::query(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;

            CREATE TABLE IF NOT EXISTS users (
                username   TEXT PRIMARY KEY,
                publicKey  TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS groups (
                groupId        TEXT PRIMARY KEY,
                groupName      TEXT NOT NULL,
                admin          TEXT NOT NULL,
                isPublic       INTEGER NOT NULL,
                isDiscoverable INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_members (
                groupId   TEXT NOT NULL,
                username  TEXT NOT NULL,
                PRIMARY KEY (groupId, username),
                FOREIGN KEY (groupId) REFERENCES groups(groupId),
                FOREIGN KEY (username) REFERENCES users(username)
            );
            CREATE TABLE IF NOT EXISTS group_invites (
                groupId  TEXT NOT NULL,
                username TEXT NOT NULL,
                PRIMARY KEY (groupId, username),
                FOREIGN KEY (groupId) REFERENCES groups(groupId),
                FOREIGN KEY (username) REFERENCES users(username)
            );
            CREATE TABLE IF NOT EXISTS pending_users (
                username  TEXT PRIMARY KEY,
                publicKey TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;
        log::info!("DbUtils initialized with db_url={}", db_url);
        Ok(DbUtils { pool })
    }

    /// Retrieve a user by username. Returns (username, publicKey).
    pub async fn get_user_by_username(&self, username: &str) -> Result<Option<(String, String)>> {
        log::info!("get_user_by_username: username={}", username);
        let row = sqlx::query("SELECT username, publicKey FROM users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        let result = row.map(|r| (r.get(0), r.get(1)));
        log::info!("get_user_by_username: result={:?}", result);
        Ok(result)
    }

    /// Add a new user. Returns true on success.
    pub async fn add_user(&self, username: &str, public_key: &str) -> Result<bool> {
        log::info!("add_user: username={}", username);
        let res = sqlx::query("INSERT OR IGNORE INTO users (username, publicKey) VALUES (?, ?)")
            .bind(username)
            .bind(public_key)
            .execute(&self.pool)
            .await?;
        let success = res.rows_affected() > 0;
        log::info!("add_user: success={}", success);
        Ok(success)
    }

    /// Create a new group. Returns true on success.
    pub async fn create_group(
        &self,
        group_id: &str,
        group_name: &str,
        admin: &str,
        is_public: bool,
        is_discoverable: bool,
    ) -> Result<bool> {
        log::info!(
            "create_group: group_id={}, group_name={}, admin={}, is_public={}, is_discoverable={}",
            group_id,
            group_name,
            admin,
            is_public,
            is_discoverable
        );
        let res = sqlx::query(
            "INSERT INTO groups (groupId, groupName, admin, isPublic, isDiscoverable) VALUES (?, ?, ?, ?, ?)"
        )
        .bind(group_id)
        .bind(group_name)
        .bind(admin)
        .bind(is_public as i64)
        .bind(is_discoverable as i64)
        .execute(&self.pool)
        .await?;
        let success = res.rows_affected() > 0;
        log::info!("create_group: success={}", success);
        Ok(success)
    }

    /// Add a member to a group. Returns true on success.
    /// Add a member to a group. Returns true on success.
    pub async fn add_group_member(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "add_group_member: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("INSERT INTO group_members (groupId, username) VALUES (?, ?)")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get all usernames of members in a group.
    pub async fn get_group_members(&self, group_id: &str) -> Result<Vec<String>> {
        log::info!("get_group_members: group_id={}", group_id);
        let rows = sqlx::query("SELECT username FROM group_members WHERE groupId = ?")
            .bind(group_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    /// Check if the user is the admin of the group.
    pub async fn is_user_admin(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "is_user_admin: group_id={}, username={}",
            group_id,
            username
        );
        let row = sqlx::query("SELECT 1 FROM groups WHERE groupId = ? AND admin = ?")
            .bind(group_id)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Check if a group is public.
    pub async fn is_group_public(&self, group_id: &str) -> Result<bool> {
        log::info!("is_group_public: group_id={}", group_id);
        let row = sqlx::query("SELECT isPublic FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Check if a group is discoverable.
    pub async fn is_group_discoverable(&self, group_id: &str) -> Result<bool> {
        log::info!("is_group_discoverable: group_id={}", group_id);
        let row = sqlx::query("SELECT isDiscoverable FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Add an invite for a user to join a private group.
    pub async fn add_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "add_group_invite: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("INSERT INTO group_invites (groupId, username) VALUES (?, ?)")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove an invite for a user.
    pub async fn remove_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "remove_group_invite: group_id={}, username={}",
            group_id,
            username
        );
        let res = sqlx::query("DELETE FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Check if a user has been invited to a group.
    pub async fn is_user_invited(&self, group_id: &str, username: &str) -> Result<bool> {
        log::info!(
            "is_user_invited: group_id={}, username={}",
            group_id,
            username
        );
        let row = sqlx::query("SELECT 1 FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Add a new pending user registration. Returns true on success.
    /// Add a new pending user registration. Returns true on success.
    pub async fn add_pending_user(&self, username: &str, public_key: &str) -> Result<bool> {
        log::info!("add_pending_user: username={}", username);
        let res =
            sqlx::query("INSERT OR IGNORE INTO pending_users (username, publicKey) VALUES (?, ?)")
                .bind(username)
                .bind(public_key)
                .execute(&self.pool)
                .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Retrieve a pending user by username. Returns the public key if found.
    pub async fn get_pending_user(&self, username: &str) -> Result<Option<String>> {
        log::info!("get_pending_user: username={}", username);
        let row = sqlx::query("SELECT publicKey FROM pending_users WHERE username = ?")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.map(|r| r.get(0)))
    }

    /// Remove a pending user registration. Returns true on success.
    pub async fn remove_pending_user(&self, username: &str) -> Result<bool> {
        log::info!("remove_pending_user: username={}", username);
        let res = sqlx::query("DELETE FROM pending_users WHERE username = ?")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Fetch all group IDs for which the given username is a member.
    pub async fn get_groups_for_user(&self, username: &str) -> Result<Vec<String>> {
        log::info!("get_groups_for_user: username={}", username);
        let rows = sqlx::query("SELECT groupId FROM group_members WHERE username = ?")
            .bind(username)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }
}
