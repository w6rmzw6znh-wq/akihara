const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'akihara-secret-key-2026-change-in-prod';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Non autorisé' });
  const token = header.split(' ')[1];
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.isAdmin) return res.status(403).json({ error: 'Admin uniquement' });
  next();
}

app.post('/api/register', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (min 6)' });

    const cleanEmail = email.trim().toLowerCase();
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(cleanEmail);
    if (exists) return res.status(400).json({ error: 'Cet email existe déjà' });

    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare('INSERT INTO users (email, password, balance) VALUES (?, ?, 1000)').run(cleanEmail, hash);
    
    const user = db.prepare('SELECT id, email, balance, is_admin, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: !!user.is_admin }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: { id: user.id, email: user.email, balance: user.balance, isAdmin: !!user.is_admin, createdAt: user.created_at }
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.trim().toLowerCase());
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: !!user.is_admin }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        balance: user.balance,
        isAdmin: !!user.is_admin,
        createdAt: user.created_at
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, balance, is_admin, created_at, last_daily, last_weekly, last_monthly FROM users WHERE id = ?').get(req.user.id);
  if (!user
