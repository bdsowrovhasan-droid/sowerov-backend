import nodemailer from "nodemailer";

let transporter = null;
function buildTransport(){
  const host = process.env.SMTP_HOST;
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE||'false') === 'true';
  const pool = String(process.env.SMTP_POOL||'true') === 'true';
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;
  if(!host || !user || !pass) return null;
  return nodemailer.createTransport({ host, port, secure, pool, auth: { user, pass } });
}

export async function sendMail({ to, subject, text, html }){
  if(String(process.env.SMTP_ENABLED||'false') !== 'true'){
    return { queued: false, reason: 'smtp_disabled' };
  }
  if(!transporter) transporter = buildTransport();
  if(!transporter) return { queued: false, reason: 'smtp_not_configured' };
  const from = process.env.SMTP_FROM || "No-Reply <no-reply@example.com>";
  try{
    const info = await transporter.sendMail({ from, to, subject, text, html });
    return { queued: true, messageId: info.messageId };
  }catch(e){
    return { queued: false, reason: e.message };
  }
}

export function otpEmailTemplate({ code, brand="Sadibook" }){
  const text = `${brand} login code: ${code}
This code will expire in 5 minutes.`;
  const html = `
  <div style="font-family:system-ui,Segoe UI,Roboto,Arial">
    <h2>${brand} login code</h2>
    <p style="font-size:16px">Use the code below to sign in. It expires in <b>5 minutes</b>.</p>
    <div style="font-size:28px;letter-spacing:4px;font-weight:700;border:1px solid #eee;border-radius:10px;padding:12px 18px;display:inline-block">
      ${code}
    </div>
    <p style="color:#666;margin-top:12px">If you didn't request this, you can ignore this email.</p>
  </div>`;
  return { text, html };
}
