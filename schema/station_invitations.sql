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
