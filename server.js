/* =====================================================
   FILE : server.js
   FUNGSI :
   - Auth
   - Verify Email + OTP
   - Chat + History
   - Streaming AI
===================================================== */

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import nodemailer from "nodemailer";

import { db } from "./db.js";
import { auth } from "./auth.js";
import { streamChat } from "./openai.js";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

/* ===== KEEP ALIVE ===== */
app.get("/ping", (req, res) => res.send("pong"));

/* ===== EMAIL ===== */
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/* ===== REGISTER ===== */
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);

  try {
    await db.run(
      "INSERT INTO users (email, password) VALUES (?,?)",
      [email, hash]
    );
    res.json({ ok: true });
  } catch {
    res.status(400).json({ error: "Email already used" });
  }
});

/* ===== SEND OTP ===== */
app.post("/api/send-otp", async (req, res) => {
  const { email } = req.body;

  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 5 * 60 * 1000;

  await db.run("DELETE FROM otps WHERE email=?", [email]);
  await db.run(
    "INSERT INTO otps (email, code, expires_at) VALUES (?,?,?)",
    [email, code, expires]
  );

  await mailer.sendMail({
    from: `"Blue Orca AI" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Kode Verifikasi Blue Orca",
    text: `Kode OTP kamu: ${code}\nBerlaku 5 menit.`
  });

  res.json({ ok: true });
});

/* ===== VERIFY OTP ===== */
app.post("/api/verify-otp", async (req, res) => {
  const { email, code } = req.body;

  const otp = await db.get(
    "SELECT * FROM otps WHERE email=? AND code=?",
    [email, code]
  );

  if (!otp || otp.expires_at < Date.now()) {
    return res.status(400).json({ error: "OTP invalid / expired" });
  }

  await db.run(
    "UPDATE users SET verified=1 WHERE email=?",
    [email]
  );
  await db.run("DELETE FROM otps WHERE email=?", [email]);

  res.json({ ok: true });
});

/* ===== LOGIN ===== */
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await db.get(
    "SELECT * FROM users WHERE email=?",
    [email]
  );
  if (!user) return res.status(400).json({ error: "User not found" });
  if (!user.verified) return res.status(403).json({ error: "Email not verified" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ error: "Wrong password" });

  const token = jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );

  res.json({ token });
});

/* ===== CREATE CHAT ===== */
app.post("/api/chat", auth, async (req, res) => {
  const result = await db.run(
    "INSERT INTO chats (user_id, title) VALUES (?,?)",
    [req.user.id, "New Chat"]
  );
  res.json({ chat_id: result.lastID });
});

/* ===== STREAM CHAT ===== */
app.post("/api/chat-stream/:chatId", auth, async (req, res) => {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Transfer-Encoding", "chunked");

  const { message } = req.body;
  const chatId = req.params.chatId;

  await db.run(
    "INSERT INTO messages (chat_id, role, content) VALUES (?,?,?)",
    [chatId, "user", message]
  );

  const history = await db.all(
    "SELECT role, content FROM messages WHERE chat_id=?",
    [chatId]
  );

  let full = "";
  const originalWrite = res.write;
  res.write = (chunk) => {
    full += chunk;
    originalWrite.call(res, chunk);
  };

  await streamChat(res, history);

  await db.run(
    "INSERT INTO messages (chat_id, role, content) VALUES (?,?,?)",
    [chatId, "assistant", full]
  );

  res.end();
});

/* ===== HISTORY ===== */
app.get("/api/chats", auth, async (req, res) => {
  const chats = await db.all(
    "SELECT * FROM chats WHERE user_id=? ORDER BY created_at DESC",
    [req.user.id]
  );
  res.json(chats);
});

app.get("/api/messages/:chatId", auth, async (req, res) => {
  const msgs = await db.all(
    "SELECT role, content FROM messages WHERE chat_id=?",
    [req.params.chatId]
  );
  res.json(msgs);
});

/* ===== START ===== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Backend running on port", PORT);
});