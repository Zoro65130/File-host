const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3000;

const DB_FILE = './filesDB.json';

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) {
      return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    }
  } catch (e) { console.log('Error loading DB:', e); }
  return {};
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

let filesDB = loadDB();
console.log('Loaded', Object.keys(filesDB).length, 'files from database');

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    const uniqueName = crypto.randomBytes(16).toString('hex') + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const ALLOWED_EXTENSIONS = /jpeg|jpg|png|gif|webp|pdf|zip|rar|7z|tar|gz|mp3|mp4|mkv|avi|mov|webm|doc|docx|xls|xlsx|ppt|pptx|txt|xml|json/;

const fileFilter = (req, file, cb) => {
  const extname = path.extname(file.originalname).toLowerCase().replace('.', '');
  const dangerousExtensions = ['exe', 'sh', 'bat', 'cmd', 'ps1', 'js', 'jar', 'scr', 'vbs', 'com', 'pif'];
  if (dangerousExtensions.includes(extname)) return cb(new Error('Dangerous file blocked!'));
  if (!ALLOWED_EXTENSIONS.test(extname)) return cb(new Error('File type not allowed!'));
  cb(null, true);
};

const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 * 1024 }, fileFilter });

app.use(express.static('public'));
app.use(express.json());

app.post('/api/upload', upload.single('file'), (req, res) => {
  const file = req.file;
  const { filePassword } = req.body;
  if (!file) return res.status(400).json({ error: 'No file!' });
  
  const downloadCode = Math.random().toString(36).substring(2, 8).toUpperCase();
  
  filesDB[downloadCode] = { 
    originalName: file.originalname, 
    filename: file.filename, 
    size: file.size, 
    filePassword: filePassword || null, 
    hasPassword: filePassword ? true : false, 
    uploadDate: new Date().toISOString(), 
    downloads: 0 
  };
  
  saveDB(filesDB);
  
  res.json({ success: true, downloadCode, link: `/download.html?code=${downloadCode}`, hasPassword: filePassword ? true : false });
});

app.post('/api/verify-file-password', (req, res) => {
  const { code, password } = req.body;
  const file = filesDB[code];
  if (!file) return res.status(404).json({ error: 'File not found!' });
  if (!file.hasPassword) return res.json({ valid: true, needsPassword: false });
  if (file.filePassword === password) return res.json({ valid: true, needsPassword: true });
  return res.json({ valid: false, needsPassword: true });
});

app.get('/api/file/:code', (req, res) => {
  const file = filesDB[req.params.code];
  if (!file) return res.status(404).json({ error: 'File not found' });
  res.json({ originalName: file.originalName, size: file.size, hasPassword: file.hasPassword });
});

app.get('/api/download/:code', (req, res) => {
  const file = filesDB[req.params.code];
  if (!file) return res.status(404).json({ error: 'File not found' });
  filesDB[req.params.code].downloads++;
  saveDB(filesDB);
  res.download(path.join('./uploads/', file.filename), file.originalName);
});

app.get('/api/captcha', (req, res) => {
  const captchaText = Math.random().toString(36).substring(2, 6).toUpperCase();
  const captchaId = crypto.randomBytes(8).toString('hex');
  global.captchas = global.captchas || {};
  global.captchas[captchaId] = captchaText;
  res.json({ captchaId, captchaText });
});

app.post('/api/verify-captcha', (req, res) => {
  const { captchaId, captchaText } = req.body;
  if (global.captchas && global.captchas[captchaId] === captchaText.toUpperCase()) { delete global.captchas[captchaId]; res.json({ valid: true }); }
  else { res.json({ valid: false }); }
});

app.use((err, req, res, next) => { if (err instanceof multer.MulterError) return res.status(400).json({ error: 'File too large!' }); else if (err) return res.status(400).json({ error: err.message }); next(); });

if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');

app.listen(PORT, () => console.log('Server running! Data saved permanently!'));