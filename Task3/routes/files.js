const express = require('express');
const multer = require('multer');
const fs = require('fs');
const crypto = require('crypto');
const router = express.Router();
const verifyToken = require('../middleware/auth');
const db = require('../db');

const upload = multer({ dest: 'uploads/' });

router.post('/upload', verifyToken, upload.single('file'), (req, res) => {
  const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const fileData = fs.readFileSync(req.file.path);
  const encrypted = Buffer.concat([cipher.update(fileData), cipher.final()]);
  const authTag = cipher.getAuthTag();

  fs.writeFileSync(req.file.path, encrypted);

  db.run(
    'INSERT INTO files (filename, owner_id, iv, authTag) VALUES (?, ?, ?, ?)',
    [req.file.filename, req.user.id, iv.toString('hex'), authTag.toString('hex')],
    function (err) {
      if (err) return res.status(500).json({ error: 'Upload failed' });
      res.status(201).json({ message: 'File uploaded and encrypted', fileId: this.lastID });
    }
  );
});

router.get('/download/:id', verifyToken, (req, res) => {
  db.get('SELECT * FROM files WHERE id = ?', [req.params.id], (err, file) => {
    if (!file) return res.status(404).json({ error: 'File not found' });

    if (file.owner_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied' });
    }

    const key = Buffer.from(process.env.ENCRYPTION_KEY, 'hex');
    const iv = Buffer.from(file.iv, 'hex');
    const authTag = Buffer.from(file.authTag, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);

    const encryptedData = fs.readFileSync(`uploads/${file.filename}`);
    const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

    // res.setHeader('Content-Disposition', `attachment; filename=downloaded_${file.filename}.txt`);
    res.send(decrypted);
  });
});

router.get('/all', verifyToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  db.all('SELECT id, filename, owner_id FROM files', [], (err, rows) => res.json(rows));
});
module.exports = router;