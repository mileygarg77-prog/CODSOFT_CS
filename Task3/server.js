require('dotenv').config();
require('./db');
const express = require('express');
const authRoutes = require('./routes/auth');
const fileRoutes = require('./routes/files');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Secure File Sharing System is running');
});

app.use('/api/auth', authRoutes);
app.use('/api/files', fileRoutes);

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});