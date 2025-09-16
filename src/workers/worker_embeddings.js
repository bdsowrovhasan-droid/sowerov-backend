/* eslint-disable no-console */
import 'dotenv/config';
import { db } from '../db.js';
import { getEmbedding } from '../utils/ai_recommendation.js';

const BATCH = parseInt(process.env.AI_REC_BACKFILL_BATCH || '200', 10);

async function run(){
  if(process.env.AI_REC_ENABLED !== 'true'){ console.log('AI_REC_ENABLED != true; exit'); return; }
  const rows = db.prepare(`
    SELECT v.id, v.title, v.tags, v.category
    FROM videos v
    LEFT JOIN video_embeddings e ON e.video_id = v.id
    WHERE e.video_id IS NULL AND v.status='APPROVED'
    ORDER BY v.id DESC LIMIT ?
  `).all(BATCH);
  for(const r of rows){
    const text = [r.title||'', r.tags||'', r.category||''].filter(Boolean).join(' | ');
    const vec = await getEmbedding(text);
    if(vec){
      db.prepare("INSERT INTO video_embeddings (video_id, vector) VALUES (?, ?)").run(r.id, JSON.stringify(vec));
      console.log('embedded video', r.id);
    } else {
      console.warn('embed failed video', r.id);
    }
  }
  console.log('done batch', rows.length);
}
run().catch(e=>{ console.error(e); process.exit(1); });
