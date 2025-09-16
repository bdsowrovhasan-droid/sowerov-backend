import Database from "better-sqlite3";
import fs from "fs";
const dbFile = process.env.DB_FILE || "data.sqlite";
const firstBoot = !fs.existsSync(dbFile);
export const db = new Database(dbFile);
if(firstBoot){
  db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS users (

      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT,
      avatar_url TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
  `);
}

/* --- Additional tables for MVP social features --- */
db.exec(`
  CREATE TABLE IF NOT EXISTS videos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT,
    hls_path TEXT NOT NULL, -- e.g. videos/hls/{videoId}/master.m3u8
    thumb_url TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_videos_user ON videos(user_id);
  CREATE INDEX IF NOT EXISTS idx_videos_created ON videos(created_at);

  CREATE TABLE IF NOT EXISTS likes (
    user_id INTEGER NOT NULL,
    video_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, video_id)
  );
  CREATE INDEX IF NOT EXISTS idx_likes_video ON likes(video_id);

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    video_id INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_comments_video ON comments(video_id);

  CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL,
    following_id INTEGER NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    PRIMARY KEY (follower_id, following_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_user INTEGER NOT NULL,
    to_user INTEGER NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(from_user, to_user);

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL, -- LIKE, COMMENT, FOLLOW, MESSAGE
    data TEXT,          -- JSON payload
    is_read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
  CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
`);

// --- Migrations (best-effort) ---
try { db.exec(`ALTER TABLE videos ADD COLUMN is_private INTEGER DEFAULT 0;
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  reporter_id INTEGER NOT NULL,
  target_type TEXT NOT NULL, -- 'video' | 'comment' | 'user'
  target_id INTEGER NOT NULL,
  reason TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS groups (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  about TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS group_members (
  group_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  role TEXT DEFAULT 'member',
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (group_id, user_id)
);
`); } catch(e) { /* ignore if already applied */ }

// --- Admin/Ban migrations ---
try {
  db.exec(`
    ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0;
    ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0;
  `);
} catch(e) { /* ignore */ }

// --- Analytics, OTP/MFA, Subscriptions, Moderation, Search (FTS) ---
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS video_views (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      video_id INTEGER NOT NULL,
      user_id INTEGER,
      bytes INTEGER DEFAULT 0,
      is_cache_hit INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_views_video ON video_views(video_id);
    CREATE INDEX IF NOT EXISTS idx_views_created ON video_views(created_at);

    CREATE TABLE IF NOT EXISTS otp_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      purpose TEXT DEFAULT 'login',
      expires_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS user_mfa (
      user_id INTEGER PRIMARY KEY,
      enabled INTEGER DEFAULT 0,
      method TEXT DEFAULT 'email' -- email for now
    );

    CREATE TABLE IF NOT EXISTS plans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      price_cents INTEGER NOT NULL,
      period_days INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO plans (code, price_cents, period_days) VALUES
      ('FREE', 0, 36500),
      ('PLUS', 29900, 30),
      ('PRO', 99900, 30);

    CREATE TABLE IF NOT EXISTS subscriptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_code TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_sub_user ON subscriptions(user_id);

    CREATE TABLE IF NOT EXISTS payments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      plan_code TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      status TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS moderation_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_type TEXT NOT NULL, -- 'VIDEO'|'COMMENT'|'USER'
      target_id INTEGER NOT NULL,
      reason TEXT,
      status TEXT DEFAULT 'PENDING',
      created_at TEXT DEFAULT (datetime('now'))
    );

    -- Extra flags
    ALTER TABLE videos ADD COLUMN requires_subscription INTEGER DEFAULT 0;
    ALTER TABLE comments ADD COLUMN flagged INTEGER DEFAULT 0;

  `);
} catch(e) { /* ignore if already exist */ }

// FTS5 for search (if available)
try {
  db.exec(`
    CREATE VIRTUAL TABLE IF NOT EXISTS videos_fts USING fts5(title, content='videos', content_rowid='id');
    CREATE TRIGGER IF NOT EXISTS videos_ai AFTER INSERT ON videos BEGIN
      INSERT INTO videos_fts(rowid, title) VALUES (new.id, coalesce(new.title,''));
    END;
    CREATE TRIGGER IF NOT EXISTS videos_ad AFTER DELETE ON videos BEGIN
      INSERT INTO videos_fts(videos_fts, rowid, title) VALUES('delete', old.id, old.title);
    END;
    CREATE TRIGGER IF NOT EXISTS videos_au AFTER UPDATE ON videos BEGIN
      INSERT INTO videos_fts(videos_fts, rowid, title) VALUES('delete', old.id, old.title);
      INSERT INTO videos_fts(rowid, title) VALUES (new.id, coalesce(new.title,''));
    END;
  `);
} catch(e) { /* FTS not available */ }


// --- AI Recommendation tables ---
try {
  db.exec(`
    CREATE TABLE IF NOT EXISTS video_embeddings (
      video_id INTEGER PRIMARY KEY,
      vector TEXT NOT NULL,
      updated_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS user_profiles (
      user_id INTEGER PRIMARY KEY,
      vector TEXT,
      updated_at TEXT DEFAULT (datetime('now'))
    );
  `);
} catch(e) { /* ignore */ }
