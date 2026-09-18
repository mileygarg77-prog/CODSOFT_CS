const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const router = express.Router();

const db = require('../db');

// SIGNUP
router.post('/signup', async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

   const hashedPassword = await bcrypt.hash(password, 10);

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, existingUser) => {
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    db.run(
      'INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
      [username, hashedPassword, role || 'user'],
      function (err) {
        if (err) {
          return res.status(500).json({ error: 'Could not create user' });
        }
        res.status(201).json({ message: 'User created successfully' });
      }
    );
  });
});

// LOGIN
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({ message: 'Login successful', token });
  });
});

module.exports = router;