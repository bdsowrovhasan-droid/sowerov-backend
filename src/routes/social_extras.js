import express from "express";
import { db } from "../db.js";
import jwt from "jsonwebtoken";
import { S3Client, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const router = express.Router();

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

// Toggle privacy
router.put("/videos/:id/privacy", auth, (req,res)=>{
  const id = Number(req.params.id);
  const { is_private } = req.body || {};
  const v = db.prepare("SELECT * FROM videos WHERE id = ?").get(id);
  if(!v) return res.status(404).json({ error: "not found" });
  if(v.user_id !== req.uid) return res.status(403).json({ error: "not owner" });
  db.prepare("UPDATE videos SET is_private = ? WHERE id = ?").run(is_private ? 1 : 0, id);
  res.json({ id, is_private: !!is_private });
});

// Playback helper: return URL based on privacy
router.get("/videos/:id/playback", (req,res)=>{
  const id = Number(req.params.id);
  const v = db.prepare("SELECT * FROM videos WHERE id = ?").get(id);
  if(!v) return res.status(404).json({ error: "not found" });
  if(v.is_private){
    // Private: signed S3 URL for master.m3u8
    const s3 = new S3Client({
      region: process.env.S3_REGION, endpoint: process.env.S3_ENDPOINT, forcePathStyle: true,
      credentials: { accessKeyId: process.env.S3_ACCESS_KEY, secretAccessKey: process.env.S3_SECRET_KEY }
    });
    const key = v.hls_path; // assumes hls_path is S3 key like videos/hls/<id>/master.m3u8
    getSignedUrl(s3, new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key }), { expiresIn: 300 })
      .then(url => res.json({ url, private: true }))
      .catch(()=> res.status(500).json({ error: "sign failed" }));
  } else {
    const base = process.env.CDN_BASE_URL || "";
    const url = (v.hls_path.startsWith("http") ? v.hls_path : `${base.replace(/\/$/,'')}/${v.hls_path}`);
    res.json({ url, private: false });
  }
});

// Reports
router.post("/reports", auth, (req,res)=>{
  const { target_type, target_id, reason } = req.body || {};
  if(!target_type || !target_id) return res.status(400).json({ error: "target_type, target_id required" });
  db.prepare("INSERT INTO reports (reporter_id, target_type, target_id, reason) VALUES (?, ?, ?, ?)")
    .run(req.uid, String(target_type).toUpperCase(), Number(target_id), reason || null);
  res.json({ ok: true });
});

// Groups
router.post("/groups", auth, (req,res)=>{
  const { name, about } = req.body || {};
  if(!name) return res.status(400).json({ error: "name required" });
  const info = db.prepare("INSERT INTO groups (owner_id, name, about) VALUES (?, ?, ?)").run(req.uid, name, about || null);
  db.prepare("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'owner')").run(info.lastInsertRowid, req.uid);
  res.json({ id: info.lastInsertRowid, name, about });
});

router.post("/groups/:id/join", auth, (req,res)=>{
  const gid = Number(req.params.id);
  try{
    db.prepare("INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')").run(gid, req.uid);
  }catch(e){}
  res.json({ group_id: gid, joined: true });
});

router.get("/groups/:id/members", (req,res)=>{
  const gid = Number(req.params.id);
  const rows = db.prepare("SELECT user_id, role FROM group_members WHERE group_id = ?").all(gid);
  res.json({ items: rows });
});

export default router;
