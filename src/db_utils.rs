use anyhow::Result;
use sqlx::{Row, SqlitePool};
use std::path::Path;

#[derive(Clone)]
pub struct DbUtils {
    pool: SqlitePool,
}

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
                publicKey  TEXT NOT NULL,
                senderTag  TEXT NOT NULL
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
                senderTag TEXT NOT NULL,
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
            "#,
        )
        .execute(&pool)
        .await?;
        Ok(DbUtils { pool })
    }

    /// Retrieve a user by username. Returns (username, publicKey, senderTag).
    pub async fn get_user_by_username(
        &self,
        username: &str,
    ) -> Result<Option<(String, String, String)>> {
        let row =
            sqlx::query("SELECT username, publicKey, senderTag FROM users WHERE username = ?")
                .bind(username)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
    }

    /// Retrieve a user by their sender tag. Returns (username, publicKey, senderTag).
    pub async fn get_user_by_sender_tag(
        &self,
        sender_tag: &str,
    ) -> Result<Option<(String, String, String)>> {
        let row =
            sqlx::query("SELECT username, publicKey, senderTag FROM users WHERE senderTag = ?")
                .bind(sender_tag)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| (r.get(0), r.get(1), r.get(2))))
    }

    /// Add a new user. Returns true on success.
    pub async fn add_user(
        &self,
        username: &str,
        public_key: &str,
        sender_tag: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO users (username, publicKey, senderTag) VALUES (?, ?, ?)",
        )
        .bind(username)
        .bind(public_key)
        .bind(sender_tag)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
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
        Ok(res.rows_affected() > 0)
    }

    /// Add a member to a group. Returns true on success.
    pub async fn add_group_member(
        &self,
        group_id: &str,
        username: &str,
        sender_tag: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO group_members (groupId, username, senderTag) VALUES (?, ?, ?)",
        )
        .bind(group_id)
        .bind(username)
        .bind(sender_tag)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Get all sender tags of members in a group.
    pub async fn get_group_member_tags(&self, group_id: &str) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT senderTag FROM group_members WHERE groupId = ?")
            .bind(group_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }

    /// Check if the sender is the admin of the group.
    pub async fn is_user_admin(&self, group_id: &str, sender_tag: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 FROM groups WHERE groupId = ? AND admin = (SELECT username FROM users WHERE senderTag = ?)"
        )
        .bind(group_id)
        .bind(sender_tag)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.is_some())
    }

    /// Check if a group is public.
    pub async fn is_group_public(&self, group_id: &str) -> Result<bool> {
        let row = sqlx::query("SELECT isPublic FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Check if a group is discoverable.
    pub async fn is_group_discoverable(&self, group_id: &str) -> Result<bool> {
        let row = sqlx::query("SELECT isDiscoverable FROM groups WHERE groupId = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.get::<i64, _>(0) != 0)
    }

    /// Add an invite for a user to join a private group.
    pub async fn add_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        let res = sqlx::query("INSERT INTO group_invites (groupId, username) VALUES (?, ?)")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Remove an invite for a user.
    pub async fn remove_group_invite(&self, group_id: &str, username: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Check if a user has been invited to a group.
    pub async fn is_user_invited(&self, group_id: &str, username: &str) -> Result<bool> {
        let row = sqlx::query("SELECT 1 FROM group_invites WHERE groupId = ? AND username = ?")
            .bind(group_id)
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Fetch all group IDs for which the given sender tag is a member.
    pub async fn get_groups_for_member(&self, sender_tag: &str) -> Result<Vec<String>> {
        let rows = sqlx::query("SELECT groupId FROM group_members WHERE senderTag = ?")
            .bind(sender_tag)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| r.get(0)).collect())
    }
}
