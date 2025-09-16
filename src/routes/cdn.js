import express from "express";
import { bunnySign } from "../utils/bunny_sign.js";

const router = express.Router();

// Example: GET /api/cdn/sign/bunny?path=/videos/hls/123/master.m3u8&ttl=300
router.get("/cdn/sign/bunny", (req,res)=>{
  const path = req.query.path;
  const ttl = Number(req.query.ttl || 300);
  const key = process.env.BUNNY_SECURITY_KEY || "";
  if(!path || !key) return res.status(400).json({ error: "path and BUNNY_SECURITY_KEY required" });
  const exp = Math.floor(Date.now()/1000) + ttl;
  const { token, expires } = bunnySign(path, exp, key);
  res.json({ token, expires });
});

export default router;

import jwt from "jsonwebtoken";

// Issue short-lived JWT to be validated by Cloudflare Worker
// GET /api/cdn/sign/cloudflare?path=/videos/hls/123/master.m3u8&ttl=300
router.get("/sign/cloudflare", (req,res)=>{
  const path = req.query.path;
  const ttl = Number(req.query.ttl || 300);
  if(!path) return res.status(400).json({ error: "path required" });
  const secret = process.env.CF_TOKEN_SECRET || process.env.JWT_SECRET || "dev_secret_change_me";
  const token = jwt.sign({ p: path }, secret, { expiresIn: ttl });
  res.json({ token, expires_in: ttl });
});


// Pre-warm CDN cache by fetching assets from CDN_BASE_URL
// body: { paths: ["/videos/hls/ID/0/seg_000.ts", ...] }
router.post("/prewarm", async (req,res)=>{
  const { paths=[] } = req.body || {};
  const base = (process.env.CDN_BASE_URL || "").replace(/\/$/,"");
  if(!base) return res.status(400).json({ error: "CDN_BASE_URL not set" });
  let ok=0, fail=0;
  await Promise.all(paths.slice(0,200).map(async p=>{
    try{
      const r = await fetch(base + p, { method: "GET" });
      if(r.ok) ok++; else fail++;
    }catch(e){ fail++; }
  }));
  res.json({ ok, fail });
});
