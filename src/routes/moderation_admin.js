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

// Approve/Reject video
router.post("/admin/videos/:id/approve", authAdmin, (req,res)=>{
  const id = Number(req.params.id);
  db.prepare("UPDATE videos SET status='APPROVED' WHERE id = ?").run(id);
  res.json({ ok: true });
});
router.post("/admin/videos/:id/reject", authAdmin, (req,res)=>{
  const id = Number(req.params.id);
  db.prepare("UPDATE videos SET status='REJECTED' WHERE id = ?").run(id);
  res.json({ ok: true });
});

// Blocklist by md5
router.post("/admin/blockhash", authAdmin, (req,res)=>{
  const { md5, reason } = req.body || {};
  if(!md5) return res.status(400).json({ error: "md5 required" });
  try{
    db.prepare("INSERT INTO blocked_hashes (md5, reason) VALUES (?, ?)").run(md5.toLowerCase(), reason||null);
  }catch(e){}
  res.json({ ok: true });
});

export default router;
