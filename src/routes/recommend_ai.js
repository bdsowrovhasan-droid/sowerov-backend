import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";
import { cosine, parseWeights } from "../utils/ai_recommendation.js";

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

router.get("/social/videos/recommend/ai", auth, (req,res)=>{
  if(process.env.AI_REC_ENABLED !== 'true') return res.status(400).json({ error: "AI recommendation disabled" });
  const { wSim, wPop, wFresh } = parseWeights();
  const uid = req.uid;
  const limit = Number(req.query.limit || 20);

  // 1) Build user profile vector: average of last 200 viewed video vectors
  const hist = db.prepare(`
    SELECT vw.video_id, e.vector
    FROM video_views vw
    JOIN video_embeddings e ON e.video_id = vw.video_id
    WHERE vw.user_id = ?
    ORDER BY vw.id DESC LIMIT 200
  `).all(uid);
  let prof = null;
  if(hist.length){
    const vecs = hist.map(r => JSON.parse(r.vector));
    const dim = vecs[0].length;
    const sum = Array(dim).fill(0);
    for(const v of vecs){ for(let i=0;i<dim;i++) sum[i]+=v[i]; }
    const norm = Math.hypot(...sum) || 1;
    prof = sum.map(x=> x / norm);
  }

  // 2) Candidate pool: approved videos with embeddings
  const pool = db.prepare(`
    SELECT v.*, e.vector,
      (SELECT COUNT(*) FROM video_views vw WHERE vw.video_id = v.id AND vw.created_at >= datetime('now','-7 day')) as popularity
    FROM videos v
    JOIN video_embeddings e ON e.video_id = v.id
    WHERE v.status='APPROVED'
    ORDER BY v.id DESC
    LIMIT 1000
  `).all();

  const now = Date.now();
  const items = pool.map((row)=>{
    const vec = JSON.parse(row.vector);
    const sim = prof ? cosine(prof, vec) : 0;
    const pop = Number(row.popularity || 0);
    const ageDays = Math.max(1, (now - new Date(row.created_at || now).getTime())/(24*3600*1000));
    const fresh = 1/ageDays; // newer => higher
    const score = (wSim*sim) + (wPop*pop) + (wFresh*fresh);
    return { v: row, score };
  }).sort((a,b)=> b.score - a.score).slice(0, limit).map(x=>x.v);

  res.json({ items, usedProfile: !!prof, weights: { wSim, wPop, wFresh } });
});

export default router;
