import express from "express";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

const router = express.Router();
async function verifyRecaptcha(token){ if(process.env.RECAPTCHA_ENABLED !== 'true') return true; if(!token) return false; try{ const p = new URLSearchParams(); p.append('secret', process.env.RECAPTCHA_SECRET||''); p.append('response', token); const r = await fetch('https://www.google.com/recaptcha/api/siteverify', { method:'POST', body:p }); const d = await r.json(); if(!d.success) return false; if(typeof d.score==='number'){ const min=parseFloat(process.env.RECAPTCHA_MIN_SCORE||'0.5'); if(d.score<min) return false; } return true; }catch(e){ return false; } }

const s3 = new S3Client({
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  forcePathStyle: true,
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY,
    secretAccessKey: process.env.S3_SECRET_KEY,
  },
});

router.post("/presign", async (req, res) => {
  try {
    const { filename, contentType, keyPrefix = "videos/raw/" , recaptchaToken } = req.body || {};
    if (!filename || !contentType) return res.status(400).json({ error: "filename, contentType required" });
    const ok = await verifyRecaptcha(recaptchaToken || req.headers['x-recaptcha']);
    if(!ok) return res.status(429).json({ error: 'recaptcha_blocked' });
    const sanitized = filename.replace(/[^a-zA-Z0-9._-]/g, "_");
    const key = `${keyPrefix}${Date.now()}-${sanitized}`;
    const cmd = new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
      ContentType: contentType,
      ACL: "public-read"
    });
    const url = await getSignedUrl(s3, cmd, { expiresIn: 600 });
    res.json({ url, key });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "presign failed" });
  }
});

export default router;
