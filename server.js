const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const { Redis } = require('@upstash/redis');

const app = express();
const PORT = process.env.PORT || 3000;

// 中间件设置
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(express.static('images'));

// 会话配置
app.use(session({
    secret: 'tg-admin-secret-key-2024',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24小时
}));

// 文件上传配置
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'images/');
    },
    filename: function (req, file, cb) {
        cb(null, file.originalname);
    }
});
const upload = multer({ storage: storage });

// 数据库初始化
const db = new sqlite3.Database('admin.db');
db.serialize(() => {
    // 创建用户表
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 创建网站配置表
    db.run(`CREATE TABLE IF NOT EXISTS site_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        download_code TEXT,
        group1 TEXT,
        group2 TEXT,
        batman_service TEXT,
        wangwang_service TEXT,
        download_url TEXT,
        backup_url TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    
    // 插入默认管理员账户
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)`, 
        ['admin', defaultPassword]);
    
    // 插入默认网站配置
    db.run(`INSERT OR IGNORE INTO site_config (download_code, group1, group2, batman_service, wangwang_service, download_url, backup_url) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        ['4271', '5977778', '7728691', '107243939', '176980', 'https://tg388.vip', 'https://tg299.vip']);
});

// 认证中间件
function requireAuth(req, res, next) {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/admin/login');
    }
}

// 路由
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 后台登录页面
app.get('/admin/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'login.html'));
});

// 后台主页
app.get('/admin', requireAuth, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin', 'dashboard.html'));
});

// 登录处理
app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: '数据库错误' });
        }
        
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.authenticated = true;
            req.session.user = { id: user.id, username: user.username };
            res.json({ success: true });
        } else {
            res.status(401).json({ error: '用户名或密码错误' });
        }
    });
});

// 登出
app.post('/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// 获取网站配置
app.get('/admin/config', requireAuth, (req, res) => {
    db.get('SELECT * FROM site_config ORDER BY id DESC LIMIT 1', (err, config) => {
        if (err) {
            return res.status(500).json({ error: '获取配置失败' });
        }
        res.json(config || {});
    });
});

// 更新网站配置
app.post('/admin/config', requireAuth, (req, res) => {
    const { download_code, group1, group2, batman_service, wangwang_service, download_url, backup_url } = req.body;
    
    db.run(`INSERT INTO site_config (download_code, group1, group2, batman_service, wangwang_service, download_url, backup_url) 
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [download_code, group1, group2, batman_service, wangwang_service, download_url, backup_url],
        function(err) {
            if (err) {
                return res.status(500).json({ error: '更新配置失败' });
            }
            
            res.json({ success: true, message: '配置更新成功' });
        });
});

// 文件上传
app.post('/admin/upload', requireAuth, upload.single('image'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ error: '没有选择文件' });
    }
    
    res.json({ 
        success: true, 
        filename: req.file.originalname,
        message: '文件上传成功' 
    });
});

// 获取文件列表
app.get('/admin/files', requireAuth, (req, res) => {
    fs.readdir('images', (err, files) => {
        if (err) {
            return res.status(500).json({ error: '读取文件失败' });
        }
        
        const imageFiles = files.filter(file => 
            /\.(jpg|jpeg|png|gif|webp)$/i.test(file)
        );
        
        res.json(imageFiles);
    });
});

// 读取环境变量
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
});

// 获取内容
app.get('/api/content', async (req, res) => {
  try {
    const data = await redis.hgetall('tg_content');
    res.json(data || {});
  } catch (e) {
    res.status(500).json({ error: '读取数据失败' });
  }
});

// 更新内容
app.post('/api/content', async (req, res) => {
  try {
    await redis.hset('tg_content', req.body);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: '保存失败' });
  }
});

// 启动服务器
app.listen(PORT, () => {
    console.log(`后台服务器运行在 http://localhost:${PORT}`);
    console.log(`后台管理地址: http://localhost:${PORT}/admin`);
    console.log(`默认登录信息: 用户名 admin, 密码 admin123`);
}); 