import express from "express";
import { db } from "../db.js";

const router = express.Router();

router.get("/search", (req,res)=>{
  const q = (req.query.q || "").trim();
  if(!q) return res.json({ items: [] });
  let rows = [];
  try {
    rows = db.prepare("SELECT v.* FROM videos_fts f JOIN videos v ON v.id = f.rowid WHERE videos_fts MATCH ? ORDER BY v.id DESC LIMIT 50").all(q+'*');
  } catch(e){
    rows = db.prepare("SELECT * FROM videos WHERE title LIKE ? ORDER BY id DESC LIMIT 50").all('%'+q+'%');
  }
  res.json({ items: rows });
});

export default router;
