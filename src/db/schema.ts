import { Database } from "bun:sqlite";

export type PostStatus = "active" | "deleted";

export interface Post {
  id: number;
  body: string;
  session_id: string;
  ip_hash: string;
  created_at: string;
  status: PostStatus;
  hugs: number;
  cares: number;
}

const db = new Database("data.sqlite", { create: true });

db.run(
  `CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    body TEXT NOT NULL,
    session_id TEXT NOT NULL,
    ip_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT CHECK (status IN ('active','deleted')) DEFAULT 'active',
    hugs INTEGER DEFAULT 0,
    cares INTEGER DEFAULT 0
  )`
);

db.run(
  `CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`
);

export { db };
