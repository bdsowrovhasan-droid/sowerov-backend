import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";

const router = express.Router();

function auth(req,res,next){
  const h = req.headers.authorization || ""; 
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  const cookieName=(process.env.AUTH_COOKIE_NAME||"sb_auth"); 
  const cookieTok = req.signedCookies?.[cookieName];
  const tok = token || cookieTok || null;
  if(!tok) return res.status(401).json({ error: "missing token" });
  try{
    const payload = jwt.verify(tok, process.env.JWT_SECRET || "dev_secret_change_me");
    req.uid = payload.uid; next();
  }catch(e){ return res.status(401).json({ error:"invalid token" }); }
}

// Recommend: mix of user category preference + global hotness + recency
router.get("/social/videos/recommend", auth, (req,res)=>{
  const uid = req.uid; const limit = Number(req.query.limit||20);
  // user preference by category (last 30d views)
  const prefs = db.prepare(`
    SELECT v.category as cat, COUNT(*) as c
    FROM video_views vw JOIN videos v ON v.id = vw.video_id
    WHERE vw.user_id = ? AND v.status='APPROVED' AND v.category IS NOT NULL
      AND vw.created_at >= datetime('now','-30 day')
    GROUP BY v.category
  `).all(uid);
  const prefMap = Object.fromEntries(prefs.map(r=>[r.cat||'', r.c]));
  const cats = prefs.map(r=>r.cat);
  // base pool: top/popular recent videos
  const pool = db.prepare(`
    SELECT v.*, 
      (SELECT COUNT(*) FROM video_views vw WHERE vw.video_id = v.id AND vw.created_at >= datetime('now','-7 day')) as popularity
    FROM videos v
    WHERE v.status='APPROVED'
    ORDER BY v.id DESC
    LIMIT 500
  `).all();
  // score
  const scored = pool.map(v=>{
    const catBoost = (v.category && prefMap[v.category]) ? prefMap[v.category] : 0;
    const score = (catBoost*3) + (v.popularity||0) + (v.id * 0.001);
    return { v, score };
  }).sort((a,b)=> b.score - a.score).slice(0, limit).map(x=>x.v);
  res.json({ items: scored, usedCategories: cats });
});

export default router;
