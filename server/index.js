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
    
    const user = db.prepare('SELECT id, email, balance, is_admin, is_moderator, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: !!user.is_admin, isModerator: !!user.is_moderator }, JWT_SECRET, { expiresIn: '30d' });

    res.json({
      token,
      user: { id: user.id, email: user.email, balance: user.balance, isAdmin: !!user.is_admin, isModerator: !!user.is_moderator, createdAt: user.created_at }
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

    const token = jwt.sign({ id: user.id, email: user.email, isAdmin: !!user.is_admin, isModerator: !!user.is_moderator }, JWT_SECRET, { expiresIn: '30d' });
    res.json({
      token,
      user: {
        id: user.id,
        email: user.email,
        balance: user.balance,
        isAdmin: !!user.is_admin,
        isModerator: !!user.is_moderator,
        createdAt: user.created_at
      }
    });
  } catch (e) {
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/me', auth, (req, res) => {
  const user = db.prepare('SELECT id, email, balance, is_admin, is_moderator, created_at, last_daily, last_weekly, last_monthly FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Utilisateur introuvable' });
  res.json({
    id: user.id,
    email: user.email,
    balance: user.balance,
    isAdmin: !!user.is_admin,
    isModerator: !!user.is_moderator,
    createdAt: user.created_at,
    lastDaily: user.last_daily,
    lastWeekly: user.last_weekly,
    lastMonthly: user.last_monthly
  });
});

app.post('/api/bonus/:type', auth, (req, res) => {
  const type = req.params.type;
  if (!['daily', 'weekly', 'monthly'].includes(type)) return res.status(400).json({ error: 'Type invalide' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  const amounts = { daily: 100, weekly: 1000, monthly: 10000 };
  const field = { daily: 'last_daily', weekly: 'last_weekly', monthly: 'last_monthly' }[type];
  const duration = { daily: 86400000, weekly: 604800000, monthly: 2592000000 }[type];

  if (user[field]) {
    const diff = Date.now() - new Date(user[field]).getTime();
    if (diff < duration) return res.status(400).json({ error: 'Bonus déjà réclamé. Reviens plus tard.' });
  }

  const amount = amounts[type];
  db.prepare(`UPDATE users SET balance = balance + ?, ${field} = datetime('now') WHERE id = ?`).run(amount, req.user.id);
  db.prepare('INSERT INTO transactions (user_id, type, amount, details) VALUES (?, ?, ?, ?)').run(req.user.id, 'bonus', amount, type);

  const balance = db.prepare('SELECT balance FROM users WHERE id = ?').get(req.user.id).balance;
  res.json({ success: true, amount, balance });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  const users = db.prepare('SELECT id, email, balance, is_admin, is_moderator, created_at FROM users ORDER BY id').all();
  res.json(users.map(u => ({ ...u, isAdmin: !!u.is_admin, isModerator: !!u.is_moderator })));
});

app.post('/api/admin/balance', auth, adminOnly, (req, res) => {
  const { userId, amount, mode } = req.body;
  if (!userId || amount === undefined) return res.status(400).json({ error: 'Paramètres manquants' });

  if (mode === 'set') {
    db.prepare('UPDATE users SET balance = ? WHERE id = ?').run(Math.max(0, parseInt(amount)), userId);
  } else {
    db.prepare('UPDATE users SET balance = MAX(0, balance + ?) WHERE id = ?').run(parseInt(amount), userId);
  }

  const user = db.prepare('SELECT id, email, balance FROM users WHERE id = ?').get(userId);
  db.prepare('INSERT INTO transactions (user_id, type, amount, details) VALUES (?, ?, ?, ?)').run(userId, 'admin', amount, mode || 'add');
  res.json(user);
});

app.post('/api/admin/moderator', auth, adminOnly, (req, res) => {
  const { userId, isModerator } = req.body;
  if (!userId) return res.status(400).json({ error: 'ID manquant' });
  db.prepare('UPDATE users SET is_moderator = ? WHERE id = ?').run(isModerator ? 1 : 0, userId);
  res.json({ success: true });
});

function getBalance(userId) {
  return db.prepare('SELECT balance FROM users WHERE id = ?').get(userId).balance;
}

function changeBalance(userId, amount) {
  db.prepare('UPDATE users SET balance = MAX(0, balance + ?) WHERE id = ?').run(amount, userId);
  return getBalance(userId);
}

app.post('/api/game/dice', auth, (req, res) => {
  const { bet, choice } = req.body;
  if (!bet || bet < 10) return res.status(400).json({ error: 'Mise minimum 10' });
  if (!['under', 'over'].includes(choice)) return res.status(400).json({ error: 'Choix invalide' });

  const balance = getBalance(req.user.id);
  if (balance < bet) return res.status(400).json({ error: 'Solde insuffisant' });

  changeBalance(req.user.id, -bet);
  const roll = Math.floor(Math.random() * 100) + 1;
  const win = (choice === 'under' && roll < 50) || (choice === 'over' && roll > 50);
  let gain = 0;
  if (win) {
    gain = Math.floor(bet * 1.95);
    changeBalance(req.user.id, gain);
  }

  res.json({ roll, win, gain, balance: getBalance(req.user.id) });
});

app.post('/api/game/slots', auth, (req, res) => {
  const { bet, type } = req.body;
  if (!bet || bet < 10) return res.status(400).json({ error: 'Mise minimum 10' });

  const balance = getBalance(req.user.id);
  if (balance < bet) return res.status(400).json({ error: 'Solde insuffisant' });

  changeBalance(req.user.id, -bet);

  const symbols = type === 'crystal' 
    ? ['💎', '💠', '🔮', '✨', '👑', '7️⃣'] 
    : ['🍒', '🍋', '🔔', '⭐', '7️⃣', '🍇'];

  const s1 = symbols[Math.floor(Math.random() * symbols.length)];
  const s2 = symbols[Math.floor(Math.random() * symbols.length)];
  const s3 = symbols[Math.floor(Math.random() * symbols.length)];

  let mult = 0;
  if (s1 === s2 && s2 === s3) {
    if (s1 === '7️⃣' || s1 === '👑') mult = 25;
    else if (s1 === '🍒' || s1 === '💎') mult = 15;
    else mult = 10;
  } else if (s1 === s2 || s2 === s3 || s1 === s3) {
    mult = 2;
  }

  let gain = 0;
  if (mult > 0) {
    gain = bet * mult;
    changeBalance(req.user.id, gain);
  }

  res.json({ symbols: [s1, s2, s3], mult, gain, balance: getBalance(req.user.id) });
});

app.post('/api/game/simple', auth, (req, res) => {
  const { bet, game } = req.body;
  if (!bet || bet < 10) return res.status(400).json({ error: 'Mise minimum 10' });

  const balance = getBalance(req.user.id);
  if (balance < bet) return res.status(400).json({ error: 'Solde insuffisant' });

  changeBalance(req.user.id, -bet);
  const win = Math.random() > 0.48;
  let gain = 0;
  if (win) {
    gain = Math.floor(bet * 1.9);
    changeBalance(req.user.id, gain);
  }

  res.json({ win, gain, balance: getBalance(req.user.id), game });
});

app.post('/api/game/mines/start', auth, (req, res) => {
  const { bet } = req.body;
  if (!bet || bet < 10) return res.status(400).json({ error: 'Mise minimum 10' });

  const balance = getBalance(req.user.id);
  if (balance < bet) return res.status(400).json({ error: 'Solde insuffisant' });

  changeBalance(req.user.id, -bet);

  const mines = [];
  while (mines.length < 5) {
    const p = Math.floor(Math.random() * 25);
    if (!mines.includes(p)) mines.push(p);
  }

  res.json({ success: true, bet, mines, balance: getBalance(req.user.id) });
});

app.post('/api/game/mines/cashout', auth, (req, res) => {
  const { bet, revealed } = req.body;
  if (!bet || !revealed || revealed < 1) return res.status(400).json({ error: 'Données invalides' });

  const mult = 1 + revealed * 0.4;
  const gain = Math.floor(bet * mult);
  changeBalance(req.user.id, gain);

  res.json({ gain, mult: mult.toFixed(2), balance: getBalance(req.user.id) });
});

app.post('/api/game/roulette', auth, (req, res) => {
  const { bets } = req.body;
  if (!bets || typeof bets !== 'object') return res.status(400).json({ error: 'Mises invalides' });

  const totalBet = Object.values(bets).reduce((a, b) => a + b, 0);
  if (totalBet < 10) return res.status(400).json({ error: 'Mise totale trop faible' });

  const balance = getBalance(req.user.id);
  if (balance < totalBet) return res.status(400).json({ error: 'Solde insuffisant' });

  changeBalance(req.user.id, -totalBet);

  const result = Math.floor(Math.random() * 37);
  const REDS = [1,3,5,7,9,12,14,16,18,19,21,23,25,27,30,32,34,36];
  const isRed = REDS.includes(result);

  let winAmount = 0;
  for (const [key, amount] of Object.entries(bets)) {
    if (key.startsWith('number-') && parseInt(key.split('-')[1]) === result) winAmount += amount * 36;
    else if (key === 'red' && isRed) winAmount += amount * 2;
    else if (key === 'black' && result !== 0 && !isRed) winAmount += amount * 2;
    else if (key === 'even' && result !== 0 && result % 2 === 0) winAmount += amount * 2;
    else if (key === 'odd' && result % 2 === 1) winAmount += amount * 2;
    else if (key === 'low' && result >= 1 && result <= 18) winAmount += amount * 2;
    else if (key === 'high' && result >= 19) winAmount += amount * 2;
    else if (key === 'dozen1' && result >= 1 && result <= 12) winAmount += amount * 3;
    else if (key === 'dozen2' && result >= 13 && result <= 24) winAmount += amount * 3;
    else if (key === 'dozen3' && result >= 25) winAmount += amount * 3;
  }

  if (winAmount > 0) changeBalance(req.user.id, winAmount);

  res.json({
    result,
    color: result === 0 ? 'green' : (isRed ? 'red' : 'black'),
    winAmount,
    balance: getBalance(req.user.id)
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

app.listen(PORT, () => {
  console.log(`🎰 Akihara Casino running on port ${PORT}`);
  console.log(`👤 Admin: zerr59 / 12345678`);
});
