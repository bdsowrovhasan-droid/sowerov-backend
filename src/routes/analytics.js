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

// Track a view (called by player or frontend)
// body: { video_id, bytes?, cache_hit? }
router.post("/track/view", (req,res)=>{
  const { video_id, bytes=0, cache_hit=0, user_id=null } = req.body || {};
  if(!video_id) return res.status(400).json({ error: "video_id required" });
  db.prepare("INSERT INTO video_views (video_id, user_id, bytes, is_cache_hit) VALUES (?, ?, ?, ?)")
    .run(Number(video_id), user_id ? Number(user_id) : null, Number(bytes)||0, cache_hit?1:0);
  res.json({ ok: true });
});

// Admin analytics summary
router.get("/admin/analytics/summary", authAdmin, (req,res)=>{
  const totalViews = db.prepare("SELECT COUNT(*) as c FROM video_views").get().c;
  const totalBytes = db.prepare("SELECT COALESCE(SUM(bytes),0) as s FROM video_views").get().s;
  const cacheHits = db.prepare("SELECT COUNT(*) as c FROM video_views WHERE is_cache_hit = 1").get().c;
  const hot = db.prepare("SELECT video_id, COUNT(*) as v FROM video_views WHERE created_at >= datetime('now','-7 day') GROUP BY video_id ORDER BY v DESC LIMIT 10").all();
  res.json({ totalViews, totalGB: (totalBytes/1e9), cacheHitRate: totalViews? (cacheHits/totalViews):0, hot });
});

// Daily timeseries (last 30d)
router.get("/admin/analytics/timeseries", authAdmin, (req,res)=>{
  const rows = db.prepare(`
    WITH days AS (
      SELECT date(datetime('now','-'|| n ||' day')) as d
      FROM (SELECT 0 n UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 UNION ALL
                   SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION ALL SELECT 9 UNION ALL
                   SELECT 10 UNION ALL SELECT 11 UNION ALL SELECT 12 UNION ALL SELECT 13 UNION ALL SELECT 14 UNION ALL
                   SELECT 15 UNION ALL SELECT 16 UNION ALL SELECT 17 UNION ALL SELECT 18 UNION ALL SELECT 19 UNION ALL
                   SELECT 20 UNION ALL SELECT 21 UNION ALL SELECT 22 UNION ALL SELECT 23 UNION ALL SELECT 24 UNION ALL
                   SELECT 25 UNION ALL SELECT 26 UNION ALL SELECT 27 UNION ALL SELECT 28 UNION ALL SELECT 29)
    )
    SELECT d as day,
           COALESCE((SELECT COUNT(*) FROM video_views WHERE date(created_at)=d),0) as views,
           COALESCE((SELECT SUM(bytes) FROM video_views WHERE date(created_at)=d),0) as bytes
    FROM days ORDER BY day ASC;
  `).all();
  res.json({ items: rows });
});


function authCookie(req,res,next){
  try{
    const name = process.env.AUTH_COOKIE_NAME || "sb_auth";
    const tok = req.signedCookies?.[name];
    if(!tok) return res.status(401).json({ error: "missing cookie" });
    const payload = jwt.verify(tok, process.env.JWT_SECRET || "dev_secret_change_me");
    req.uid = payload.uid; next();
  }catch(e){ return res.status(401).json({ error: "invalid token" }); }
}

// Authenticated view with implicit user
router.post("/track/view-auth", authCookie, (req,res)=>{
  const { video_id, bytes=0, cache_hit=1 } = req.body || {};
  if(!video_id) return res.status(400).json({ error: "video_id required" });
  db.prepare("INSERT INTO video_views (video_id, user_id, bytes, is_cache_hit) VALUES (?, ?, ?, ?)")
    .run(Number(video_id), Number(req.uid), Number(bytes)||0, cache_hit?1:0);
  res.json({ ok: true });
});

export default router;

