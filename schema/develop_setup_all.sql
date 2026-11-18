-- RadioConnect: install all current tables on NEW EMPTY DEVELOP D1 ONLY.
-- Database ID: 455e49e5-a229-4d3b-bb0b-0c5da14092c9
-- NEVER execute on the production D1 database.

-- ===== 0001_stations.sql =====
-- RadioConnect D1 schema v1 (not applied automatically)
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 auth_subject TEXT NOT NULL UNIQUE,
 display_name TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS stations (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 2 AND 80),
 visibility TEXT NOT NULL DEFAULT 'private' CHECK(visibility IN ('private','public')),
 owner_user_id TEXT NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS station_members (
 station_id TEXT NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','dj','member')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(station_id,user_id)
);
CREATE TABLE IF NOT EXISTS rooms (
 id TEXT PRIMARY KEY,
 station_id TEXT NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
 name TEXT NOT NULL,
 visibility TEXT NOT NULL DEFAULT 'members' CHECK(visibility IN ('members','admins')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_station_members_user ON station_members(user_id);
CREATE INDEX IF NOT EXISTS idx_rooms_station ON rooms(station_id);
-- Server implementation requirements:
-- 1. Verify identity from a trusted authentication provider, never a client user ID.
-- 2. In one transaction insert station, owner membership and initial rooms.
-- 3. Authorize every station/room/file operation by station_members.
-- 4. No public storage object URLs for private stations.
-- 5. Enforce limits and rate limiting; never accept client-supplied owner_user_id.

-- ===== 0002_auth.sql =====
-- Apply after schema/0001_stations.sql
CREATE TABLE IF NOT EXISTS credentials(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,salt TEXT NOT NULL,password_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_attempts(key TEXT PRIMARY KEY,count INTEGER NOT NULL,window_start INTEGER NOT NULL);

-- ===== station_invitations.sql =====
-- Run once against the RadioConnect PREVIEW D1 database only.
CREATE TABLE IF NOT EXISTS station_invitations (
 id TEXT PRIMARY KEY NOT NULL,
 station_id TEXT NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
 email TEXT NOT NULL,
 invited_by TEXT NOT NULL REFERENCES users(id),
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 accepted_at INTEGER,
 UNIQUE(station_id,email)
);
CREATE INDEX IF NOT EXISTS idx_station_invitations_email ON station_invitations(email,expires_at);

-- ===== chat_messages.sql =====
-- RadioConnect private chat, run once in Cloudflare D1 SQL console.
-- Creates only new objects; preserves existing tables and records.
CREATE TABLE IF NOT EXISTS chat_messages (
  id TEXT PRIMARY KEY NOT NULL,
  room_id TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 2000),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_chat_messages_room_created ON chat_messages(room_id, created_at DESC);

-- ===== dj_profiles.sql =====
-- Apply to PREVIEW D1 only before enabling DJ profiles.
CREATE TABLE IF NOT EXISTS dj_profiles (
 user_id TEXT PRIMARY KEY NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 dj_name TEXT NOT NULL DEFAULT '',
 bio TEXT NOT NULL DEFAULT '',
 photo_url TEXT NOT NULL DEFAULT '',
 social_url TEXT NOT NULL DEFAULT '',
 updated_at INTEGER NOT NULL
);

-- ===== station_audit_log.sql =====
-- Apply only to the RadioConnect preview D1 database.
CREATE TABLE IF NOT EXISTS station_audit_log (
 id TEXT PRIMARY KEY NOT NULL,
 station_id TEXT NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
 actor_user_id TEXT NOT NULL REFERENCES users(id),
 action TEXT NOT NULL,
 target_user_id TEXT,
 details TEXT NOT NULL DEFAULT '{}',
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_station_audit_log_station_date ON station_audit_log(station_id,created_at DESC);

-- ===== direct_messages.sql =====
-- Apply only to PREVIEW D1. Messages are restricted to users sharing a station.
CREATE TABLE IF NOT EXISTS direct_messages (
 id TEXT PRIMARY KEY NOT NULL,
 station_id TEXT NOT NULL REFERENCES stations(id) ON DELETE CASCADE,
 sender_user_id TEXT NOT NULL REFERENCES users(id),
 recipient_user_id TEXT NOT NULL REFERENCES users(id),
 message TEXT NOT NULL CHECK(length(message) BETWEEN 1 AND 2000),
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_direct_messages_pair ON direct_messages(station_id,sender_user_id,recipient_user_id,created_at DESC);
CREATE INDEX IF NOT EXISTS idx_direct_messages_recipient ON direct_messages(station_id,recipient_user_id,created_at DESC);

-- ===== chat_enhancements.sql =====
-- Apply only to preview D1, after chat_messages.sql.
CREATE TABLE IF NOT EXISTS chat_message_reactions (
 message_id TEXT NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 emoji TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(message_id,user_id,emoji)
);
CREATE TABLE IF NOT EXISTS chat_message_pins (
 message_id TEXT PRIMARY KEY REFERENCES chat_messages(id) ON DELETE CASCADE,
 pinned_by TEXT NOT NULL REFERENCES users(id),
 pinned_at INTEGER NOT NULL
);

-- ===== user_notifications.sql =====
-- Preview D1 only. In-app notification inbox (not Web Push subscriptions).
CREATE TABLE IF NOT EXISTS user_notifications (
 id TEXT PRIMARY KEY NOT NULL,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 station_id TEXT REFERENCES stations(id) ON DELETE CASCADE,
 kind TEXT NOT NULL,
 title TEXT NOT NULL,
 detail TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 read_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_user_notifications_inbox ON user_notifications(user_id,created_at DESC);

