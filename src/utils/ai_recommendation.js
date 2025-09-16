export async function getEmbedding(text){
  if(process.env.AI_REC_ENABLED !== 'true') return null;
  const endpoint = process.env.AI_REC_ENDPOINT;
  const key = process.env.AI_REC_API_KEY;
  const dim = parseInt(process.env.AI_REC_DIM || '768', 10);
  try{
    const r = await fetch(endpoint, {
      method:'POST',
      headers:{ 'Content-Type':'application/json', 'Authorization': `Bearer ${key}` },
      body: JSON.stringify({ input: text, type: 'embedding' })
    });
    const data = await r.json();
    let vec = data.embedding || data.vector || data[0] || null;
    if(!vec || !Array.isArray(vec)) return null;
    // normalize & clamp dimension
    if(vec.length > dim) vec = vec.slice(0, dim);
    if(vec.length < dim) vec = vec.concat(Array(dim - vec.length).fill(0));
    const norm = Math.hypot(...vec) || 1;
    return vec.map(x=> x / norm);
  }catch(e){
    return null;
  }
}

export function cosine(a, b){
  if(!a || !b || a.length !== b.length) return 0;
  let s = 0;
  for(let i=0;i<a.length;i++) s += a[i]*b[i];
  return s; // already normalized
}

export function parseWeights(){
  const [w1, w2, w3] = (process.env.AI_REC_WEIGHTS || '0.6,0.3,0.1').split(',').map(x=>parseFloat(x.trim())||0);
  return { wSim:w1, wPop:w2, wFresh:w3 };
}
