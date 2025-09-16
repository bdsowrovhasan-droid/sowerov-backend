import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";

const router = express.Router();

function authAdmin(req,res,next){
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  try{
    const payload = jwt.verify(token || "", process.env.JWT_SECRET || "dev_secret_change_me");
    const u = db.prepare("SELECT is_admin FROM users WHERE id = ?").get(payload.uid);
    if(!u || !u.is_admin) return res.status(403).json({ error: "admin only" });
    next();
  }catch(e){ return res.status(401).json({ error: "invalid token" }); }
}

router.get("/moderation/queue", authAdmin, (req,res)=>{
  const rows = db.prepare("SELECT * FROM moderation_queue WHERE status='PENDING' ORDER BY id DESC LIMIT 200").all();
  res.json({ items: rows });
});

router.post("/moderation/queue/:id/resolve", authAdmin, (req,res)=>{
  const id = Number(req.params.id);
  const { action } = req.body || {}; // 'approve' | 'delete'
  const m = db.prepare("SELECT * FROM moderation_queue WHERE id = ?").get(id);
  if(!m) return res.status(404).json({ error: "not found" });
  if(action === 'delete'){
    if(m.target_type === 'COMMENT') db.prepare("DELETE FROM comments WHERE id = ?").run(m.target_id);
    if(m.target_type === 'VIDEO') db.prepare("DELETE FROM videos WHERE id = ?").run(m.target_id);
  }
  db.prepare("UPDATE moderation_queue SET status = 'RESOLVED' WHERE id = ?").run(id);
  res.json({ ok: true });
});

export default router;
