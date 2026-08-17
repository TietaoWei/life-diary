const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 10000;

if (!process.env.DATABASE_URL) {
  console.error('缺少环境变量 DATABASE_URL，请在 Render 中配置 Neon 连接串');
}

// 使用 Neon Postgres（免费、持久）
const isNeon = (process.env.DATABASE_URL || '').includes('neon');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isNeon ? { rejectUnauthorized: false } : undefined
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'life-diary-local-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 1000 * 60 * 60 * 24 * 7 }
}));

// 静态资源
app.use('/assets', express.static(path.join(__dirname, 'assets')));
app.get('/colors_and_type.css', (req, res) => res.sendFile(path.join(__dirname, 'colors_and_type.css')));
app.get('/favicon.png', (req, res) => res.sendFile(path.join(__dirname, 'favicon.png')));

function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.redirect('/login.html');
}

// 注册
app.post('/api/register', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();
  if (!username || !password) {
    return res.status(400).json({ error: '用户名和密码不能为空' });
  }
  if (username.length < 2 || password.length < 6) {
    return res.status(400).json({ error: '用户名至少 2 个字符，密码至少 6 位' });
  }

  try {
    const existing = await pool.query(
      'SELECT 1 FROM users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: '该用户名已被注册' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO users (id, username, password_hash) VALUES ($1, $2, $3)',
      [id, username, passwordHash]
    );

    req.session.userId = id;
    req.session.username = username;
    res.json({ ok: true, username });
  } catch (e) {
    console.error('注册失败：', e.message);
    if (e.code === '23505') {
      return res.status(409).json({ error: '该用户名已被注册' });
    }
    res.status(500).json({ error: '服务器错误，请稍后重试' });
  }
});

// 登录
app.post('/api/login', async (req, res) => {
  const username = (req.body.username || '').trim();
  const password = (req.body.password || '').trim();

  try {
    const result = await pool.query(
      'SELECT id, username, password_hash FROM users WHERE LOWER(username) = LOWER($1)',
      [username]
    );
    const user = result.rows[0];
    if (!user) return res.status(401).json({ error: '用户名或密码错误' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: '用户名或密码错误' });

    req.session.userId = user.id;
    req.session.username = user.username;
    res.json({ ok: true, username: user.username });
  } catch (e) {
    console.error('登录失败：', e.message);
    res.status(500).json({ error: '服务器错误，请稍后重试' });
  }
});

// 登出
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.json({ ok: true });
  });
});

// 当前用户
app.get('/api/me', (req, res) => {
  if (req.session && req.session.userId) {
    res.json({ loggedIn: true, username: req.session.username });
  } else {
    res.status(401).json({ loggedIn: false });
  }
});

// 登录页（公开）
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// 受保护页面（从 pages 目录映射到根路径，保持相对资源路径不变）
app.get('/', requireAuth, (req, res) => res.redirect('/home.html'));
app.get('/home.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'home.html')));
app.get('/create.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'create.html')));
app.get('/me.html', requireAuth, (req, res) => res.sendFile(path.join(__dirname, 'pages', 'me.html')));

async function start() {
  try {
    await initDb();
    console.log('数据库连接成功');
  } catch (e) {
    console.error('数据库初始化失败：', e.message);
  }
  app.listen(PORT, () => {
    console.log('碎碎念服务已启动，端口：' + PORT);
  });
}

start();
