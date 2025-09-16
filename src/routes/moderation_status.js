import express from "express";
import { db } from "../db.js";

const router = express.Router();

router.get("/moderation/status/:id", (req,res)=>{
  const id = Number(req.params.id);
  const v = db.prepare("SELECT id, status FROM videos WHERE id = ?").get(id);
  if(!v) return res.status(404).json({ error: "not found" });
  res.json(v);
});

export default router;
