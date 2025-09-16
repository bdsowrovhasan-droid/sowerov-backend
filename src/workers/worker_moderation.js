/* eslint-disable no-console */
import 'dotenv/config';
import { db } from '../db.js';
import { moderateText, moderateImages } from '../utils/ai_moderation.js';

/**
 * Usage:
 *   node src/workers/worker_moderation.js
 * or with pm2:
 *   pm2 start src/workers/worker_moderation.js --name moderation
 *
 * Strategy:
 * - Poll videos with status='PENDING' (or 'PENDING_AI' if you use such flag)
 * - Check title/description with moderateText()
 * - (Optional) Sample frames -> signed URLs -> moderateImages()
 * - Decide: APPROVE / REVIEW / REJECT
 * - Write decision to videos.status + moderation_queue if REVIEW/REJECT
 */

const BATCH = 20;
const SLEEP_MS = 5000;

function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

async function runOnce(){
  const rows = db.prepare("SELECT * FROM videos WHERE status = 'PENDING' ORDER BY id ASC LIMIT ?").all(BATCH);
  for(const v of rows){
    try{
      // 1) Text moderation (title only for now; you can add description if you store it)
      const textRes = await moderateText({ title: v.title || '' });
      let label = textRes.label;
      let reasons = textRes.reasons || [];

      // 2) (Optional) Image moderation for thumbnails (if available)
      let imgLabel = 'APPROVE';
      if (v.thumb_url) {
        try {
          const imgRes = await moderateImages({ images: [v.thumb_url] });
          imgLabel = imgRes.label;
          reasons = reasons.concat(imgRes.reasons || []);
        } catch {}
      }

      // Decision merge: REJECT dominates, then REVIEW, else APPROVE
      const final = (label === 'REJECT' || imgLabel === 'REJECT') ? 'REJECT'
                   : (label === 'REVIEW' || imgLabel === 'REVIEW') ? 'REVIEW'
                   : 'APPROVE';

      if(final === 'APPROVE'){
        db.prepare("UPDATE videos SET status='APPROVED' WHERE id = ?").run(v.id);
        console.log("APPROVED", v.id);
      } else if(final === 'REVIEW'){
        // keep PENDING and add to moderation_queue for human review
        db.prepare("INSERT INTO moderation_queue (target_type, target_id, reason) VALUES ('VIDEO', ?, ?)").run(v.id, reasons.join(','));
        console.log("REVIEW queued", v.id);
      } else {
        db.prepare("UPDATE videos SET status='REJECTED' WHERE id = ?").run(v.id);
        db.prepare("INSERT INTO moderation_queue (target_type, target_id, reason) VALUES ('VIDEO', ?, ?)").run(v.id, reasons.join(','));
        console.log("REJECTED", v.id);
      }

    }catch(e){
      console.warn("Moderation error video", v.id, e.message);
    }
  }
}

async function loop(){
  console.log("AI moderation worker started");
  while(true){
    await runOnce();
    await sleep(SLEEP_MS);
  }
}
loop().catch(err=>{ console.error(err); process.exit(1); });
