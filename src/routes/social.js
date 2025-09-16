import Filter from "bad-words";
import { Server } from "socket.io";
import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";

const router = express.Router();
const banned = (process.env.MODERATION_KEYWORDS||'').toLowerCase().split(',').map(x=>x.trim()).filter(Boolean);
const io = globalThis.__io || null;


// Reuse simple auth from server.js by verifying token here
function auth(req,res,next){
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if(!token) return res.status(401).json({ error: "missing token" });
  try{
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_secret_change_me");
    req.uid = payload.uid;
    next();
  }catch(e){
    return res.status(401).json({ error: "invalid token" });
  }
}

// Create video record (after upload/transcode)
router.post("/videos", auth, (req,res)=>{
  const { title, hls_path, thumb_url, category, tags } = req.body || {};
  if(!hls_path) return res.status(400).json({ error: "hls_path required" });
  // Auto-moderation: check banned keywords
  let status = "PENDING";
  if(process.env.AI_MOD_ENABLED === 'true') { status = 'PENDING'; }
  const keywords = (process.env.MODERATION_KEYWORDS||"").toLowerCase().split(",").map(s=>s.trim()).filter(Boolean);
  const t = (title||"").toLowerCase();
  const strict = String(process.env.STRICT_MODERATION||"false").toLowerCase()==="true";
  if(keywords.length && keywords.some(k=>k && t.includes(k))) status = "REJECTED";
  else if(!strict) status = "APPROVED";
  const info = db.prepare("INSERT INTO videos (user_id, title, hls_path, thumb_url, category, tags, status) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(req.uid, title || null, hls_path, thumb_url || null, category || null, tags || null, status);
  const video = db.prepare("SELECT * FROM videos WHERE id = ?").get(info.lastInsertRowid);
  res.json({ video });
});

// List/feed (basic, newest first, optional search by title)
router.get("/videos", (req,res)=>{
  const { q, limit=20, offset=0 } = req.query;
  let rows;
  if(q){
    rows = db.prepare("SELECT * FROM videos WHERE status = 'APPROVED' AND title LIKE ? ORDER BY id DESC LIMIT ? OFFSET ?")
      .all(`%${q}%`, Number(limit), Number(offset));
  } else {
    rows = db.prepare("SELECT * FROM videos WHERE status = 'APPROVED' ORDER BY id DESC LIMIT ? OFFSET ?")
      .all(Number(limit), Number(offset));
  }
  res.json({ items: rows });
});

// Like / Unlike
router.post("/videos/:id/like", auth, (req,res)=>{
  const id = Number(req.params.id);
  try{
    db.prepare("INSERT INTO likes (user_id, video_id) VALUES (?, ?)").run(req.uid, id);
    // notify owner
    const owner = db.prepare("SELECT user_id FROM videos WHERE id = ?").get(id);
    if(owner && owner.user_id !== req.uid){
      db.prepare("INSERT INTO notifications (user_id, type, data) VALUES (?, ?, ?)")
        .run(owner.user_id, "LIKE", JSON.stringify({ from:req.uid, video_id:id }));
      try{ io && io.to(`user:${owner.user_id}`).emit('notify', { type:'LIKE', from:req.uid, video_id:id }); }catch(e){}
    }
  }catch(e){}
  const count = db.prepare("SELECT COUNT(*) as c FROM likes WHERE video_id = ?").get(id).c;
  res.json({ liked: true, likes: count });
});

router.delete("/videos/:id/like", auth, (req,res)=>{
  const id = Number(req.params.id);
  db.prepare("DELETE FROM likes WHERE user_id = ? AND video_id = ?").run(req.uid, id);
  const count = db.prepare("SELECT COUNT(*) as c FROM likes WHERE video_id = ?").get(id).c;
  res.json({ liked: false, likes: count });
});

router.get("/videos/:id/likes/count", (req,res)=>{
  const id = Number(req.params.id);
  const count = db.prepare("SELECT COUNT(*) as c FROM likes WHERE video_id = ?").get(id).c;
  res.json({ likes: count });
});

// Comments
router.get("/videos/:id/comments", (req,res)=>{
  const id = Number(req.params.id);
  const rows = db.prepare(`
    SELECT c.id, c.text, c.created_at, u.name as author_name, u.id as author_id
    FROM comments c JOIN users u ON u.id = c.user_id
    WHERE c.video_id = ? ORDER BY c.id DESC LIMIT 100
  `).all(id);
  res.json({ items: rows });
});

router.post("/videos/:id/comments", auth, (req,res)=>{
  const id = Number(req.params.id);
  const { text } = req.body || {};
  if(!text) return res.status(400).json({ error: "text required" });
  if(text.length > 2000) return res.status(400).json({ error: "comment too long" });
  try { const filter = new Filter(); if(filter.isProfane(text)) return res.status(400).json({ error: "profanity blocked" }); } catch {}
  const info = db.prepare("INSERT INTO comments (user_id, video_id, text) VALUES (?, ?, ?)")
    .run(req.uid, id, text);
  // notify owner
  const owner = db.prepare("SELECT user_id FROM videos WHERE id = ?").get(id);
  if(owner && owner.user_id !== req.uid){
    db.prepare("INSERT INTO notifications (user_id, type, data) VALUES (?, ?, ?)" )
      .run(owner.user_id, "COMMENT", JSON.stringify({ from:req.uid, video_id:id, comment_id: info.lastInsertRowid }));
  try{ io && io.to(`user:${owner.user_id}`).emit('notify', { type:'COMMENT', from:req.uid, video_id:id }); }catch(e){}
  }
  const row = db.prepare("SELECT * FROM comments WHERE id = ?").get(info.lastInsertRowid);
  res.json({ comment: row });
});

// Follow / Unfollow
router.post("/follow/:userId", auth, (req,res)=>{
  const target = Number(req.params.userId);
  if(target === req.uid) return res.status(400).json({ error: "cannot follow self" });
  try{
    db.prepare("INSERT INTO follows (follower_id, following_id) VALUES (?, ?)").run(req.uid, target);
    db.prepare("INSERT INTO notifications (user_id, type, data) VALUES (?, ?, ?)")
      .run(target, "FOLLOW", JSON.stringify({ from:req.uid }));
  }catch(e){}
  res.json({ following: true });
});

router.delete("/follow/:userId", auth, (req,res)=>{
  const target = Number(req.params.userId);
  db.prepare("DELETE FROM follows WHERE follower_id = ? AND following_id = ?").run(req.uid, target);
  res.json({ following: false });
});

// Notifications
router.get("/notifications", auth, (req,res)=>{
  const rows = db.prepare("SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100")
    .all(req.uid);
  res.json({ items: rows });
});
router.post("/notifications/:id/read", auth, (req,res)=>{
  db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?").run(Number(req.params.id), req.uid);
  res.json({ ok: true });
});

// Simple messages (polling)
router.get("/messages", auth, (req,res)=>{
  const withId = Number(req.query.with);
  const rows = db.prepare(`
    SELECT * FROM messages
    WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?)
    ORDER BY id DESC LIMIT 100
  `).all(req.uid, withId, withId, req.uid).reverse();
  res.json({ items: rows });
});
router.post("/messages", auth, (req,res)=>{
  const { to_user, text } = req.body || {};
  if(!to_user || !text) return res.status(400).json({ error: "to_user, text required" });
  const info = db.prepare("INSERT INTO messages (from_user, to_user, text) VALUES (?, ?, ?)")
    .run(req.uid, Number(to_user), text);
  // notify recipient
  if(Number(to_user) !== req.uid){
    db.prepare("INSERT INTO notifications (user_id, type, data) VALUES (?, ?, ?)")
      .run(Number(to_user), "MESSAGE", JSON.stringify({ from:req.uid }));
  }
  const row = db.prepare("SELECT * FROM messages WHERE id = ?").get(info.lastInsertRowid);
  res.json({ message: row });
});

export default router;
