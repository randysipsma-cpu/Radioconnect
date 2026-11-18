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
