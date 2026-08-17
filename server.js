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
    CREATE TABLE IF NOT EXISTS posts (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL,
      content TEXT NOT NULL,
      image TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS comments (
      id UUID PRIMARY KEY,
      post_id UUID NOT NULL,
      user_id UUID NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);
  await pool.query('ALTER TABLE posts ADD COLUMN IF NOT EXISTS image TEXT');
}

app.use(express.json({ limit: '15mb' }));
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

function requireAuthApi(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ loggedIn: false, error: '请先登录' });
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

// 发布动态
app.post('/api/posts', requireAuthApi, async (req, res) => {
  const content = (req.body.content || '').trim();
  const image = typeof req.body.image === 'string' && req.body.image.startsWith('data:image/') ? req.body.image : null;
  if (!content && !image) return res.status(400).json({ error: '内容不能为空' });
  try {
    const id = crypto.randomUUID();
    await pool.query(
      'INSERT INTO posts (id, user_id, content, image) VALUES ($1, $2, $3, $4)',
      [id, req.session.userId, content, image]
    );
    res.json({ ok: true, id });
  } catch (e) {
    console.error('发布失败：', e.message);
    res.status(500).json({ error: '发布失败，请稍后重试' });
  }
});

// 获取当前用户的动态
app.get('/api/posts', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.id, p.content, p.image, p.created_at,
              (SELECT COUNT(*) FROM comments c WHERE c.post_id = p.id) AS comment_count
       FROM posts p WHERE p.user_id = $1 ORDER BY p.created_at DESC, p.id DESC`,
      [req.session.userId]
    );
    res.json({ ok: true, posts: result.rows });
  } catch (e) {
    console.error('获取动态失败：', e.message);
    res.status(500).json({ error: '获取动态失败' });
  }
});

// 删除动态
app.delete('/api/posts/:id', requireAuthApi, async (req, res) => {
  try {
    await pool.query('DELETE FROM comments WHERE post_id = $1', [req.params.id]);
    const result = await pool.query(
      'DELETE FROM posts WHERE id = $1 AND user_id = $2',
      [req.params.id, req.session.userId]
    );
    if (result.rowCount === 0) return res.status(404).json({ error: '动态不存在' });
    res.json({ ok: true });
  } catch (e) {
    console.error('删除失败：', e.message);
    res.status(500).json({ error: '删除失败，请稍后重试' });
  }
});

// 获取某条动态的评论
app.get('/api/posts/:id/comments', requireAuthApi, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT c.id, c.content, c.created_at FROM comments c JOIN posts p ON p.id = c.post_id WHERE c.post_id = $1 AND p.user_id = $2 ORDER BY c.created_at ASC',
      [req.params.id, req.session.userId]
    );
    res.json({ ok: true, comments: result.rows });
  } catch (e) {
    console.error('获取评论失败：', e.message);
    res.status(500).json({ error: '获取评论失败' });
  }
});

// 发表评论
app.post('/api/posts/:id/comments', requireAuthApi, async (req, res) => {
  const content = (req.body.content || '').trim();
  if (!content) return res.status(400).json({ error: '评论不能为空' });
  try {
    const post = await pool.query('SELECT id FROM posts WHERE id = $1 AND user_id = $2', [req.params.id, req.session.userId]);
    if (post.rowCount === 0) return res.status(404).json({ error: '动态不存在' });
    const id = crypto.randomUUID();
    await pool.query('INSERT INTO comments (id, post_id, user_id, content) VALUES ($1, $2, $3, $4)', [id, req.params.id, req.session.userId, content]);
    res.json({ ok: true, id });
  } catch (e) {
    console.error('发表评论失败：', e.message);
    res.status(500).json({ error: '发表评论失败' });
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
