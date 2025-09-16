/**
 * AI Moderation Utility (provider-agnostic)
 * Returns: { label: 'APPROVE'|'REVIEW'|'REJECT', score: number, reasons: string[] }
 */
export async function moderateText({ title = '', description = '' }){
  if (process.env.AI_MOD_ENABLED !== 'true') return { label: 'APPROVE', score: 0, reasons: [] };
  const endpoint = process.env.AI_MOD_ENDPOINT;
  const key = process.env.AI_MOD_API_KEY;
  const threshold = parseFloat(process.env.AI_MOD_THRESHOLD || '0.7');

  // Minimal generic protocol: POST { type:'text', title, description } -> { score, categories }
  try{
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({ type:'text', title, description })
    });
    const data = await r.json();
    const score = Number(data.score || 0);
    const label = score >= threshold ? 'REJECT' : (score >= (threshold*0.8) ? 'REVIEW' : 'APPROVE');
    return { label, score, reasons: data.categories || [] };
  }catch(e){
    return { label: 'REVIEW', score: 0, reasons: ['mod_error'] };
  }
}

/**
 * Image moderation: pass an array of absolute URLs (CDN) or S3 keys mapped to signed URLs by caller.
 * Input: { images: [url1, url2, ...] }
 */
export async function moderateImages({ images = [] }){
  if (process.env.AI_MOD_ENABLED !== 'true') return { label: 'APPROVE', score: 0, reasons: [] };
  const endpoint = process.env.AI_MOD_ENDPOINT;
  const key = process.env.AI_MOD_API_KEY;
  const threshold = parseFloat(process.env.AI_MOD_THRESHOLD || '0.7');

  try{
    const r = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({ type:'image', images })
    });
    const data = await r.json();
    const score = Number(data.score || 0);
    const label = score >= threshold ? 'REJECT' : (score >= (threshold*0.8) ? 'REVIEW' : 'APPROVE');
    return { label, score, reasons: data.categories || [] };
  }catch(e){
    return { label: 'REVIEW', score: 0, reasons: ['mod_error'] };
  }
}
