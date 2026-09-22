import type {ProcessResult} from '../types';
export async function processPayload(payload:string,payloadId:string):Promise<ProcessResult>{
 const started=performance.now();
 try{
  const r=await fetch('/process',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({payload,payload_id:payloadId})});
  const latency=Math.round(performance.now()-started); const retryAfter=r.headers.get('Retry-After')||undefined;
  let data:any={}; try{data=await r.json()}catch{}
  if(!r.ok){const e:any=new Error(data?.error||data?.message||`HTTP ${r.status}`);e.status=r.status;e.retryAfter=retryAfter;e.latency=latency;throw e}
  return {result:data.result,latency,status:r.status,retryAfter};
 }catch(e:any){if(e.status)throw e; const x:any=new Error('Не удалось подключиться к Go-серверу на localhost:8080');x.status=0;x.latency=Math.round(performance.now()-started);throw x}
}
export const uuid=()=>crypto.randomUUID();
export const detectTypes=(s:string)=>{const a:string[]=[];if(/\b\d{4}\s?\d{6}\b/.test(s))a.push('PASSPORT');if(/\b(?:\d[ -]*?){13,19}\b/.test(s))a.push('CARD');if(/[А-ЯЁ][а-яё]+\s+[А-ЯЁ][а-яё]+(?:\s+[А-ЯЁ][а-яё]+)?/.test(s))a.push('FIO');if(/\+?\d[\d\s()-]{8,}/.test(s))a.push('PHONE');if(/[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}/.test(s))a.push('EMAIL');return [...new Set(a)]};
