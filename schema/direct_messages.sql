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
