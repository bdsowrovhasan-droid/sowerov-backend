import rateLimit from "express-rate-limit";
import { createAdapter } from "@socket.io/redis-adapter";
import { createClient } from "redis";
import http from "http";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import dotenv from "dotenv";
import { db } from "./src/db.js";
function requireNotBanned(uid){ const u = db.prepare("SELECT is_banned FROM users WHERE id = ?").get(uid); if(u && u.is_banned) { const e=new Error("banned"); e.status=403; throw e; } }
import { hashSync, genSaltSync, compareSync } from "bcryptjs";
import jwt from "jsonwebtoken";

import uploadRoutes from "./src/routes/upload.js";
import socialRoutes from "./src/routes/social.js";
import socialExtras from "./src/routes/social_extras.js";
import adminRoutes from "./src/routes/admin.js";
import cdnRoutes from "./src/routes/cdn.js";
import { sendMail, otpEmailTemplate } from "./src/utils/mailer.js";
import analyticsRoutes from "./src/routes/analytics.js";
import moderationRoutes from "./src/routes/moderation.js";
import searchRoutes from "./src/routes/search.js";
import modAdminRoutes from "./src/routes/moderation_admin.js";
import recommendRoutes from "./src/routes/recommend.js";
import moderationStatusRoutes from "./src/routes/moderation_status.js";
import recommendAiRoutes from "./src/routes/recommend_ai.js";

dotenv.config();
import { Server } from "socket.io";

const app = express();
const otpHits = new Map();
function otpRateOk(email){
  const now = Date.now();
  const windowMs = 60*1000; const max = Number(process.env.SMTP_RATE_PER_MIN||30);
  const key = email.toLowerCase();
  const arr = (otpHits.get(key)||[]).filter(t=> now - t < windowMs);
  if(arr.length >= max) return false; arr.push(now); otpHits.set(key, arr); return true;
}
app.set('trust proxy', 1);
const server = http.createServer(app);
app.use(helmet());
const cspDirectives = {
  defaultSrc: (process.env.CSP_DEFAULT_SRC || "'self'").split(/\s+/),
  scriptSrc: (process.env.CSP_SCRIPT_SRC || "'self'").split(/\s+/),
  styleSrc: (process.env.CSP_STYLE_SRC || "'self'").split(/\s+/),
  imgSrc: (process.env.CSP_IMG_SRC || "'self' data:").split(/\s+/),
  mediaSrc: (process.env.CSP_MEDIA_SRC || "'self'").split(/\s+/),
  connectSrc: (process.env.CSP_CONNECT_SRC || "'self'").split(/\s+/),
  frameSrc: (process.env.CSP_FRAME_SRC || "'self'").split(/\s+/),
  objectSrc: (process.env.CSP_OBJECT_SRC || "'none'").split(/\s+/),
};
app.use(helmet.contentSecurityPolicy({ directives: cspDirectives }));
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev_cookie_secret'));
function enforceHttps(req,res,next){
  if(process.env.ENFORCE_HTTPS === "true"){
    if(req.secure || req.headers['x-forwarded-proto'] === 'https'){ return next(); }
    const url = 'https://' + req.headers.host + req.originalUrl;
    return res.redirect(301, url);
  }
  next();
}
app.use(enforceHttps);
function adminIpAllowlist(req, res, next){
  const ips = (process.env.ADMIN_IPS || "").split(",").map(x=>x.trim()).filter(Boolean);
  if(ips.length === 0) return next();
  const ip = (req.headers['x-forwarded-for'] || req.ip || '').toString().split(',')[0].trim();
  if(ips.includes(ip)) return next();
  return res.status(403).json({ error: "admin ip blocked", yourIp: ip });
}


app.use(express.json());

// Rate limits
const limiterAuth = rateLimit({ windowMs: 10 * 60 * 1000, limit: 50 });
const limiterUpload = rateLimit({ windowMs: 10 * 60 * 1000, limit: 120 });
const limiterSocial = rateLimit({ windowMs: 10 * 60 * 1000, limit: 300 });
const limiterComment = rateLimit({ windowMs: 10 * 60 * 1000, limit: 60 });
const limiterMessage = rateLimit({ windowMs: 10 * 60 * 1000, limit: 120 });

const limiterAuth = rateLimit({ windowMs: 10 * 60 * 1000, limit: 50 }); // 50 per 10min
const limiterUpload = rateLimit({ windowMs: 10 * 60 * 1000, limit: 120 }); // 120 per 10min
app.use("/api/auth/", limiterAuth);
app.use("/api/upload/", limiterUpload);
app.use("/api/social", limiterSocial);

app.use(cors({ origin: (origin, cb)=>{ const allow = (process.env.ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean); if(!origin) return cb(null, true); if(allow.length===0 || allow.includes(origin)) return cb(null, true); return cb(new Error("CORS blocked"), false); }, credentials: true }));

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Health
app.get("/api/health", (req,res)=>res.json({ ok: true }));

// Register
app.post("/api/auth/register", async (req,res)=>{
  const { name, email, password, recaptchaToken } = req.body || {};
  if(!name || !email || !password) return res.status(400).json({ error: "name, email, password required" });
  const vr = await verifyRecaptcha(recaptchaToken || req.headers["x-recaptcha"]); if(!vr.ok) return res.status(429).json({ error: "recaptcha_blocked", reason: vr.reason });
  const userRow = db.prepare("SELECT id FROM users WHERE email = ?").get(email.toLowerCase());
  if(userRow) return res.status(409).json({ error: "email already registered" });
  const salt = genSaltSync(10);
  const password_hash = hashSync(password, salt);
  const info = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)").run(name, email.toLowerCase(), password_hash);
  const user = db.prepare("SELECT id, name, email, bio, avatar_url FROM users WHERE id = ?").get(info.lastInsertRowid);
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ token, user });
});

// Login
app.post("/api/auth/login", async (req,res)=>{
  const { email, password, recaptchaToken } = req.body || {};
  if(!email || !password) return res.status(400).json({ error: "email, password required" });
  const vr2 = await verifyRecaptcha(recaptchaToken || req.headers["x-recaptcha"]); if(!vr2.ok) return res.status(429).json({ error: "recaptcha_blocked", reason: vr2.reason });
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
  if(!user) return res.status(401).json({ error: "invalid credentials" });
  const ok = compareSync(password, user.password_hash || "");
  if(!ok) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "7d" });
  const safeUser = { id: user.id, name: user.name, email: user.email, bio: user.bio, avatar_url: user.avatar_url };
  const cookieName = process.env.AUTH_COOKIE_NAME || "sb_auth";
  res.cookie(cookieName, token, { httpOnly:true, secure:true, sameSite:"strict", signed:true, maxAge: 7*24*3600*1000 });
  res.json({ token, user: safeUser });
});

// Simple auth middleware
function auth(req,res,next){
  const h = req.headers.authorization || ""; const cookieName=(process.env.AUTH_COOKIE_NAME||"sb_auth"); const cookieTok = req.signedCookies?.[cookieName];
  const token = h.startsWith("Bearer ") ? h.slice(7) : cookieTok || null;
  if(!token) return res.status(401).json({ error: "missing token" });
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.uid = payload.uid;
    try{ requireNotBanned(req.uid); } catch(e){ return res.status(e.status||403).json({ error: 'banned' }); }
    next();
  }catch(e){
    return res.status(401).json({ error: "invalid token" });
  }
}

// Profile
app.get("/api/profile", auth, (req,res)=>{
  const user = db.prepare("SELECT id, name, email, bio, avatar_url FROM users WHERE id = ?").get(req.uid);
  res.json({ user });
});

app.put("/api/profile", auth, (req,res)=>{
  const { name, bio, avatar_url } = req.body || {};
  db.prepare("UPDATE users SET name = COALESCE(?, name), bio = COALESCE(?, bio), avatar_url = COALESCE(?, avatar_url) WHERE id = ?")
    .run(name ?? null, bio ?? null, avatar_url ?? null, req.uid);
  const updated = db.prepare("SELECT id, name, email, bio, avatar_url FROM users WHERE id = ?").get(req.uid);
  res.json({ user: updated });
});

// Upload routes
app.use('/api/upload', uploadRoutes);
app.use('/api/social', socialRoutes);
app.use('/api/social', socialExtras);
app.use('/api/admin', adminIpAllowlist, adminRoutes);
app.use('/api/cdn', cdnRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api', moderationRoutes);
app.use('/api', searchRoutes);
app.use('/api', modAdminRoutes);
app.use('/api', recommendRoutes);
app.use('/api', moderationStatusRoutes);
app.use('/api', recommendAiRoutes);

const port = process.env.PORT || 5050;
server.listen(port, ()=> console.log(`Auth API listening on http://localhost:${port}`));


// --- Socket.IO real-time ---
const io = new Server(server, { cors: { origin: process.env.ORIGIN?.split(",") || "*", credentials: true } });

// Redis adapter (optional if REDIS_URL set)
(async () => {
  try{
    if(process.env.REDIS_URL){
      const pubClient = createClient({ url: process.env.REDIS_URL });
      const subClient = pubClient.duplicate();
      await pubClient.connect(); await subClient.connect();
      io.adapter(createAdapter(pubClient, subClient));
      console.log("Socket.IO using Redis adapter");
    }
  }catch(e){ console.warn("Redis adapter disabled:", e.message); }
})();

function socketAuthMiddleware(socket, next){
  try {
    const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace("Bearer ","");
    if(!token) return next(new Error("missing token"));
    const payload = jwt.verify(token, JWT_SECRET);
    socket.data.uid = payload.uid;
    return next();
  } catch(e){ return next(new Error("invalid token")); }
}

io.use(socketAuthMiddleware);
io.on("connection", (socket) => {
  const uid = socket.data.uid;
  socket.join(`user:${uid}`);
  console.log("socket connected uid=", uid);

  socket.on("chat:send", ({ to, text }) => {
    if(!to || !text) return;
    io.to(`user:${to}`).emit("chat:recv", { from: uid, text, ts: Date.now() });
  });

  socket.on("typing", ({ to }) => {
    if(!to) return;
    io.to(`user:${to}`).emit("typing", { from: uid, ts: Date.now() });
  });
  socket.on("chat:delivered", ({ from }) => {
    if(!from) return;
    io.to(`user:${from}`).emit("chat:delivered-ack", { to: uid, ts: Date.now() });
  });
  socket.on("chat:read", ({ from }) => {
    if(!from) return;
    io.to(`user:${from}`).emit("chat:read-ack", { to: uid, ts: Date.now() });
  });

  socket.on("disconnect", ()=>{
    // cleanup
  });
});

  const uid = socket.data.uid;
  socket.join(`user:${uid}`);
  console.log("socket connected uid=", uid);

  socket.on("chat:send", ({ to, text }) => {
    if(!to || !text) return;
    // Basic profanity filter
    try{
      const Filter = require('bad-words'); const filter = new Filter();
      if(filter.isProfane(text)) return; // drop
    }catch{}
    // emit to recipient room
    io.to(`user:${to}`).emit("chat:recv", { from: uid, text, ts: Date.now() });
  });

  socket.on("disconnect", ()=>{
    // cleanup if needed
  });
});

globalThis.__io = io;

async function verifyRecaptcha(token){
  if(process.env.RECAPTCHA_ENABLED !== "true") return { ok: true, score: 1 };
  if(!token) return { ok: false, reason: "missing recaptcha token" };
  try{
    const params = new URLSearchParams();
    params.append("secret", process.env.RECAPTCHA_SECRET || "");
    params.append("response", token);
    const r = await fetch("https://www.google.com/recaptcha/api/siteverify", { method:"POST", body: params });
    const data = await r.json();
    if(!data.success) return { ok: false, reason: "recaptcha failed" };
    if(typeof data.score === "number"){
      const min = parseFloat(process.env.RECAPTCHA_MIN_SCORE || "0.5");
      if(data.score < min) return { ok: false, reason: "low score" };
    }
    return { ok: true };
  }catch(e){ return { ok: false, reason: "recaptcha error" }; }
}



// OTP (email-like) - demo: returns code in response; in production, send via email/SMS
app.post("/api/auth/request-otp", async (req,res)=>{
  const { email, purpose = "login" } = req.body || {};
  if(!email) return res.status(400).json({ error: "email required" });
  if(!otpRateOk(email)) return res.status(429).json({ error: "rate_limited" });
  const code = String(Math.floor(100000 + Math.random()*900000));
  const ttl = Date.now() + 5*60*1000;
  db.prepare("INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)")
    .run(email.toLowerCase(), code, purpose, ttl);

  // send email via SMTP
  const tpl = otpEmailTemplate({ code, brand: process.env.BRAND_NAME || "Sadibook" });
  const mail = await sendMail({ to: email, subject: (process.env.BRAND_NAME||"Sadibook")+" login code", text: tpl.text, html: tpl.html });

  // Only expose demo_code if SMTP disabled (for local testing)
  if(mail.queued){
    return res.json({ ok: true });
  } else {
    return res.json({ ok: true, demo_code: code, note: mail.reason || "smtp_disabled" });
  }
});
  const code = String(Math.floor(100000 + Math.random()*900000));
  const ttl = Date.now() + 5*60*1000;
  db.prepare("INSERT INTO otp_codes (email, code, purpose, expires_at) VALUES (?, ?, ?, ?)")
    .run(email.toLowerCase(), code, purpose, ttl);
  res.json({ ok: true, demo_code: code }); // TODO: send via email
});

// login-otp
app.post("/api/auth/login-otp", async (req,res)=>{
  const { email, code } = req.body || {};
  if(!email || !code) return res.status(400).json({ error: "email, code required" });
  const row = db.prepare("SELECT * FROM otp_codes WHERE email = ? AND code = ? ORDER BY id DESC").get(email.toLowerCase(), code);
  if(!row || row.expires_at < Date.now()) return res.status(401).json({ error: "invalid/expired code" });
  // find or create user
  let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email.toLowerCase());
  if(!user){
    const info = db.prepare("INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)").run(email.split("@")[0], email.toLowerCase(), "otp_login");
    user = db.prepare("SELECT * FROM users WHERE id = ?").get(info.lastInsertRowid);
  }
  // MFA check: if user_mfa enabled, require second factor (skip here since email is MFA)
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "7d" });
  const safeUser = { id: user.id, name: user.name, email: user.email, bio: user.bio, avatar_url: user.avatar_url };
  const cookieName = process.env.AUTH_COOKIE_NAME || "sb_auth";
  res.cookie(cookieName, token, { httpOnly:true, secure:true, sameSite:"strict", signed:true, maxAge: 7*24*3600*1000 });
  res.json({ token, user: safeUser });
});
