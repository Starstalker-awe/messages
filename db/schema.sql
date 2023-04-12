CREATE TABLE IF NOT EXISTS users(
  u_id VARCHAR(32) PRIMARY KEY UNIQUE NOT NULL,
  username TEXT NOT NULL,
  bio TEXT,
  email TEXT,
  public BOOLEAN DEFAULT 1 NOT NULL,
  phash TEXT,
  p_id VARCHAR(32) NOT NULL,
  pfp PATH,
  active BOOLEAN DEFAULT 1 NOT NULL,
  createed DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL,
  last_login DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS user_search ON users (u_id, p_id, username, email);
CREATE INDEX IF NOT EXISTS active_users ON users (active);

/* Implement blocking users later */

CREATE TABLE IF NOT EXISTS messages (
  id VARCHAR(32) PRIMARY KEY UNIQUE NOT NULL,
  reply VARCHAR(32),
  sender VARCHAR(32) NOT NULL,
  reciever VARCHAR(32) NOT NULL,
  content TEXT NOT NULL,
  stamped DATETIME NOT NULL,
  FOREIGN KEY (sender) REFERENCES users(id),
  FOREIGN KEY (reciever) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS message_search ON messages (id, sender, reciever);
CREATE INDEX IF NOT EXISTS message_content ON messages (content);


/* Schema for exploits.db, saved in same file */
CREATE TABLE IF NOT EXISTS exploits (
  id VARCHAR(32) PRIMARY KEY UNIQUE NOT NULL,
  ip VARCHAR(45) NOT NULL,
  vpn_chance DECIMAL,
  exploit TEXT NOT NULL,
  created DATETIME DEFAULT CURRENT_TIMESTAMP NOT NULL
);