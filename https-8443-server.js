const express = require('express');
const https = require('https');
const http = require('http');
const fs = require('fs');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

console.log('启动HTTPS服务器 (端口8443)...');

const app = express();
const HTTP_PORT = 8080;  // 使用8080端口避免冲突
const HTTPS_PORT = 8443; // 使用8443端口避免冲突
const JWT_SECRET = 'lengthwords-secret-2024';

let users = [];
const DATA_DIR = '/opt/lengthwords/data';

// 确保数据目录存在
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// 加载用户数据
try {
  if (fs.existsSync(DATA_DIR + '/users.json')) {
    users = JSON.parse(fs.readFileSync(DATA_DIR + '/users.json', 'utf8'));
    console.log('加载用户数据:', users.length, '个用户');
  }
} catch (e) {
  console.log('用户数据加载失败，使用空数据');
}

// 保存用户数据
function saveUsers() {
  try {
    fs.writeFileSync(DATA_DIR + '/users.json', JSON.stringify(users, null, 2));
    console.log('用户数据已保存');
  } catch (e) {
    console.error('保存失败:', e.message);
  }
}

// 中间件
app.use(cors({ 
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// 日志中间件
app.use((req, res, next) => {
  console.log(new Date().toISOString(), req.method, req.url);
  next();
});

// 测试接口
app.get('/api/test', (req, res) => {
  console.log('处理测试请求');
  res.json({
    success: true,
    message: '🎉 英语学习API服务器运行正常 (HTTPS:8443)',
    timestamp: new Date().toISOString(),
    users: users.length,
    protocol: req.secure ? 'HTTPS' : 'HTTP',
    port: req.secure ? HTTPS_PORT : HTTP_PORT,
    server: 'lengthwords API v1.0'
  });
});

// 注册接口
app.post('/api/register', async (req, res) => {
  console.log('处理注册请求:', req.body);
  
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: '用户名和密码不能为空' 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        error: '密码长度至少6位' 
      });
    }
    
    // 检查用户是否存在
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        error: '用户名已存在' 
      });
    }
    
    // 创建新用户
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = users.length + 1;
    
    const newUser = {
      id: userId,
      username: username,
      password: hashedPassword,
      created_at: new Date().toISOString()
    };
    
    users.push(newUser);
    saveUsers();
    
    // 生成token
    const token = jwt.sign({ userId: userId }, JWT_SECRET, { expiresIn: '7d' });
    
    console.log('用户注册成功:', username);
    res.json({
      success: true,
      message: '注册成功',
      token: token,
      userId: userId,
      username: username
    });
    
  } catch (error) {
    console.error('注册错误:', error);
    res.status(500).json({ 
      success: false,
      error: '注册失败' 
    });
  }
});

// 登录接口
app.post('/api/login', async (req, res) => {
  console.log('处理登录请求:', req.body);
  
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        error: '用户名和密码不能为空' 
      });
    }
    
    // 查找用户
    const user = users.find(u => u.username === username);
    if (!user) {
      return res.status(400).json({ 
        success: false,
        error: '用户不存在' 
      });
    }
    
    // 验证密码
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ 
        success: false,
        error: '密码错误' 
      });
    }
    
    // 生成token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
    
    console.log('用户登录成功:', username);
    res.json({
      success: true,
      message: '登录成功',
      token: token,
      userId: user.id,
      username: username
    });
    
  } catch (error) {
    console.error('登录错误:', error);
    res.status(500).json({ 
      success: false,
      error: '登录失败' 
    });
  }
});

// JWT验证中间件
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = null;
  
  if (authHeader) {
    // 支持两种格式：
    // 1. "Bearer eyJhbGciOiJIUzI1NiI..."
    // 2. "eyJhbGciOiJIUzI1NiI..."
    if (authHeader.startsWith('Bearer ')) {
      token = authHeader.split(' ')[1];
    } else {
      token = authHeader;
    }
  }
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      error: '需要登录' 
    });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      console.error('JWT验证失败:', err.message);
      return res.status(403).json({ 
        success: false,
        error: '无效token' 
      });
    }
    req.userId = user.userId;
    next();
  });
}

// 学习统计接口
app.get('/api/learning/stats', authenticateToken, (req, res) => {
  console.log('获取学习统计, 用户ID:', req.userId);
  res.json({
    success: true,
    totalWords: 0,
    todayLearned: 0,
    todayTarget: 10,
    todayProgress: 0,
    learningStreak: 0,
    reviewCount: 0
  });
});

// 404处理
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: '接口不存在',
    availableRoutes: [
      'GET /api/test',
      'POST /api/register',
      'POST /api/login',
      'GET /api/learning/stats'
    ]
  });
});

// 错误处理
app.use((err, req, res, next) => {
  console.error('服务器错误:', err);
  res.status(500).json({ 
    success: false,
    error: '服务器内部错误' 
  });
});

// 启动服务器
function startServer() {
  const sslKeyPath = '/opt/lengthwords/lengthwords.top.key';
  const sslCertPath = '/opt/lengthwords/lengthwords.top.pem';
  
  let hasSSL = false;
  try {
    hasSSL = fs.existsSync(sslKeyPath) && fs.existsSync(sslCertPath);
    console.log('SSL证书检查:', hasSSL ? '✅ 找到证书' : '❌ 未找到证书');
  } catch (e) {
    console.log('SSL检查失败:', e.message);
  }
  
  if (hasSSL) {
    console.log('启动HTTPS服务器...');
    try {
      const credentials = {
        key: fs.readFileSync(sslKeyPath, 'utf8'),
        cert: fs.readFileSync(sslCertPath, 'utf8')
      };
      
      const httpsServer = https.createServer(credentials, app);
      
      httpsServer.on('error', (err) => {
        console.error('HTTPS服务器错误:', err.message);
        if (err.code === 'EADDRINUSE') {
          console.error('端口' + HTTPS_PORT + '被占用，请检查其他服务');
          process.exit(1);
        }
      });
      
      httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
        console.log('🔒 HTTPS服务器启动成功!');
        console.log('🌐 端口:', HTTPS_PORT);
        console.log('🔗 HTTPS地址: https://lengthwords.top:8443/api/test');
        console.log('📱 小程序API地址: https://lengthwords.top:8443');
      });
      
      // HTTP重定向到HTTPS
      const httpApp = express();
      httpApp.use('*', (req, res) => {
        const httpsUrl = 'https://' + req.headers.host.replace(':8080', ':8443') + req.url;
        res.redirect(301, httpsUrl);
      });
      
      const httpServer = http.createServer(httpApp);
      httpServer.on('error', (err) => {
        if (err.code !== 'EADDRINUSE') {
          console.error('HTTP服务器错误:', err.message);
        }
      });
      
      httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
        console.log('🔄 HTTP重定向服务器启动，端口:', HTTP_PORT);
      });
      
    } catch (e) {
      console.error('HTTPS启动失败:', e.message);
      console.log('请检查SSL证书文件是否存在且有效');
      process.exit(1);
    }
  } else {
    console.error('❌ 未找到SSL证书文件，无法启动HTTPS服务器');
    console.log('SSL证书路径:');
    console.log('  Key:', sslKeyPath);
    console.log('  Cert:', sslCertPath);
    process.exit(1);
  }
}

// 进程错误处理
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('未处理的Promise拒绝:', reason);
  process.exit(1);
});

// 优雅关闭
process.on('SIGTERM', () => {
  console.log('收到SIGTERM信号，正在关闭服务器...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('收到SIGINT信号，正在关闭服务器...');
  process.exit(0);
});

console.log('初始化服务器...');
console.log('当前用户数:', users.length);
startServer();
