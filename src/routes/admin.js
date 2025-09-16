import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";

const router = express.Router();

function auth(req,res,next){
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if(!token) return res.status(401).json({ error: "missing token" });
  try{
    const payload = jwt.verify(token, process.env.JWT_SECRET || "dev_secret_change_me");
    req.uid = payload.uid;
    const u = db.prepare("SELECT is_admin FROM users WHERE id = ?").get(req.uid);
    if(!u || !u.is_admin) return res.status(403).json({ error: "admin only" });
    next();
  }catch(e){ return res.status(401).json({ error: "invalid token" }); }
}

// Reports
router.get("/admin/reports", auth, (req,res)=>{
  const rows = db.prepare("SELECT * FROM reports ORDER BY id DESC LIMIT 200").all();
  res.json({ items: rows });
});

router.post("/admin/reports/:id/resolve", auth, (req,res)=>{
  const id = Number(req.params.id);
  const { action } = req.body || {}; // 'dismiss' | 'delete_video' | 'delete_comment' | 'ban_user'
  const r = db.prepare("SELECT * FROM reports WHERE id = ?").get(id);
  if(!r) return res.status(404).json({ error: "not found" });

  if(action === "delete_video" && r.target_type === "VIDEO"){
    db.prepare("DELETE FROM videos WHERE id = ?").run(r.target_id);
  } else if(action === "delete_comment" && r.target_type === "COMMENT"){
    db.prepare("DELETE FROM comments WHERE id = ?").run(r.target_id);
  } else if(action === "ban_user" && r.target_type === "USER"){
    db.prepare("UPDATE users SET is_banned = 1 WHERE id = ?").run(r.target_id);
  }
  db.prepare("DELETE FROM reports WHERE id = ?").run(id);
  res.json({ ok: true });
});

// Users
router.get("/admin/users", auth, (req,res)=>{
  const rows = db.prepare("SELECT id, name, email, is_admin, is_banned, created_at FROM users ORDER BY id DESC LIMIT 200").all();
  res.json({ items: rows });
});
router.post("/admin/users/:id/ban", auth, (req,res)=>{
  db.prepare("UPDATE users SET is_banned = 1 WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});
router.post("/admin/users/:id/unban", auth, (req,res)=>{
  db.prepare("UPDATE users SET is_banned = 0 WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});
router.post("/admin/users/:id/make-admin", auth, (req,res)=>{
  db.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});

// Content
router.delete("/admin/videos/:id", auth, (req,res)=>{
  db.prepare("DELETE FROM videos WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});
router.delete("/admin/comments/:id", auth, (req,res)=>{
  db.prepare("DELETE FROM comments WHERE id = ?").run(Number(req.params.id));
  res.json({ ok: true });
});

export default router;
