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

/* ---------- helpers ---------- */
function requireNotBanned(uid) {
  const u = db.prepare("SELECT is_banned FROM users WHERE id = ?").get(uid);
  if (u && u.is_banned) {
    const e = new Error("banned");
    e.status = 403;
    throw e;
  }
}

/* ---------- app & server ---------- */
const app = express();
app.set("trust proxy", 1);
const server = http.createServer(app);

/* ---------- security headers / CSP ---------- */
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

/* ---------- cookies ---------- */
app.use(cookieParser(process.env.COOKIE_SECRET || "dev_cookie_secret"));

/* ---------- HTTPS enforce (Render/X-Forwarded-Proto aware) ---------- */
function enforceHttps(req, res, next) {
  if (process.env.ENFORCE_HTTPS === "true") {
    if (req.secure || req.headers["x-forwarded-proto"] === "https") return next();
    const url = "https://" + req.headers.host + req.originalUrl;
    return res.redirect(301, url);
  }
  next();
}
app.use(enforceHttps);

/* ---------- optional admin IP allowlist ---------- */
function adminIpAllowlist(req, res, next) {
  const ips = (process.env.ADMIN_IPS || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  if (ips.length === 0) return next();
  const ip = (req.headers["x-forwarded-for"] || req.ip || "")
    .toString()
    .split(",")[0]
    .trim();
  if (ips.includes(ip)) return next();
  return res.status(403).json({ error: "admin ip blocked", yourIp: ip });
}

/* ---------- body parsing ---------- */
app.use(express.json());

/* ---------- CORS ---------- */
app.use(
  cors({
    origin: (origin, cb) => {
      const allow = (process.env.ORIGIN || "")
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      if (!origin) return cb(null, true); // Postman ইত্যাদির জন্য
      if (allow.length === 0 || allow.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"), false);
    },
    credentials: true,
  })
);

/* ---------- OTP per-minute throttle (in-memory) ---------- */
const otpHits = new Map();
function otpRateOk(email) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const max = Number(process.env.SMTP_RATE_PER_MIN || 30);
  const key = (email || "").toLowerCase();
  const arr = (otpHits.get(key) || []).filter((t) => now - t < windowMs);
  if (arr.length >= max) return false;
  arr.push(now);
  otpHits.set(key, arr);
  return true;
}

/* ---------- rate limiters (define ONCE!) ---------- */
const limiterAuth = rateLimit({ windowMs: 10 * 60 * 1000, limit: 50 });
const limiterUpload = rateLimit({ windowMs: 10 * 60 * 1000, limit: 120 });
const limiterSocial = rateLimit({ windowMs: 10 * 60 * 1000, limit: 300 });
const limiterComment = rateLimit({ windowMs: 10 * 60 * 1000, limit: 60 });
const limiterMessage = rateLimit({ windowMs: 10 * 60 * 1000, limit: 120 });

/* ---------- health check ---------- */
app.get("/healthz", (req, res) => {
  res.status(200).json({ ok: true, ts: Date.now() });
});

/* ---------- routes & per-route limits ---------- */
app.use("/api/auth", limiterAuth); // যদি আলাদা auth রুট যোগ করো, এখানে বসাও
app.use("/api/upload", limiterUpload, uploadRoutes);
app.use("/api/social", limiterSocial, socialRoutes);
app.use("/api/social-extras", socialExtras);
app.use("/api/admin", adminIpAllowlist, adminRoutes);
app.use("/api/cdn", cdnRoutes);
app.use("/api/analytics", analyticsRoutes);
app.use("/api/moderation", moderationRoutes);
app.use("/api/moderation-admin", adminIpAllowlist, modAdminRoutes);
app.use("/api/moderation-status", moderationStatusRoutes);
app.use("/api/recommend", recommendRoutes);
app.use("/api/recommend-ai", recommendAiRoutes);
app.use("/api/search", searchRoutes);

/* ---------- simple 404 ---------- */
app.use((req, res, next) => {
  res.status(404).json({ error: "not_found" });
});

/* ---------- central error handler ---------- */
app.use((err, req, res, next) => {
  const status = err.status || 500;
  const msg = err.message || "server_error";
  res.status(status).json({ error: msg });
});

/* ---------- socket.io (optional Redis adapter) ---------- */
const io = new Server(server, {
  path: "/socket.io",
  cors: {
    origin: (origin, cb) => {
      const allow = (process.env.ORIGIN || "")
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean);
      if (!origin) return cb(null, true);
      if (allow.length === 0 || allow.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"), false);
    },
    credentials: true,
  },
});

if (process.env.REDIS_URL) {
  const pubClient = createClient({ url: process.env.REDIS_URL });
  const subClient = pubClient.duplicate();
  await pubClient.connect();
  await subClient.connect();
  io.adapter(createAdapter(pubClient, subClient));
}

/* ---------- start server ---------- */
const PORT = Number(process.env.PORT || 10000);
server.listen(PORT, () => {
  console.log(`API listening on :${PORT}`);
});

