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
