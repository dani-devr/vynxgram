const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();

// Criar pastas necessárias (banco de dados e uploads)
const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// Middlewares com limite aumentado para suportar requisições maiores
app.use(express.json({ limit: '1024mb' }));
app.use(express.urlencoded({ limit: '1024mb', extended: true }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuração de Upload de Arquivos (1GB limite)
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage, limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB

// Sessão de Utilizador
const sessionMiddleware = session({
    store: new SQLiteStore({ dir: './data', db: 'sessions.db' }),
    secret: process.env.SESSION_SECRET || 'segredo_padrao_vynxgram',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true }
});
app.use(sessionMiddleware);
io.use((socket, next) => sessionMiddleware(socket.request, {}, next));

// Base de Dados SQLite
const db = new sqlite3.Database(path.join(dataDir, 'vynxgram.db'));
const dbRun = (sql, params = []) => new Promise((res, rej) => db.run(sql, params, function(err) { err ? rej(err) : res(this) }));
const dbGet = (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (err, row) => err ? rej(err) : res(row)));
const dbAll = (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));

async function initDB() {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, display_name TEXT, avatar TEXT, bio TEXT, status TEXT DEFAULT 'Online', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, name TEXT, icon TEXT, owner_id TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS channels (id TEXT PRIMARY KEY, server_id TEXT, name TEXT, type TEXT DEFAULT 'text', created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);
    await dbRun(`CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, channel_id TEXT, user_id TEXT, content TEXT, file_url TEXT, file_type TEXT, file_name TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`);

    const globalServer = await dbGet("SELECT id FROM servers WHERE name = 'Comunidade Global'");
    if (!globalServer) {
        const serverId = crypto.randomUUID();
        await dbRun("INSERT INTO servers (id, name, owner_id) VALUES (?, ?, ?)", [serverId, 'Comunidade Global', 'system']);
        await dbRun("INSERT INTO channels (id, server_id, name) VALUES (?, ?, ?)", [crypto.randomUUID(), serverId, 'geral']);
        await dbRun("INSERT INTO channels (id, server_id, name) VALUES (?, ?, ?)", [crypto.randomUUID(), serverId, 'convívio']);
    }
}
initDB().catch(console.error);

const requireAuth = (req, res, next) => req.session.userId ? next() : res.status(401).json({ error: 'Não autorizado' });

// --- ROTAS DA API ---
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password || password.length < 4) return res.status(400).json({ error: 'Dados inválidos.' });
        if (await dbGet('SELECT id FROM users WHERE username = ?', [username])) return res.status(400).json({ error: 'Nome de utilizador em uso.' });
        
        const hash = await bcrypt.hash(password, 10);
        const id = crypto.randomUUID();
        await dbRun('INSERT INTO users (id, username, password_hash, display_name) VALUES (?, ?, ?, ?)', [id, username, hash, username]);
        
        req.session.userId = id;
        res.json({ success: true, user: { id, username, display_name: username } });
    } catch (err) { res.status(500).json({ error: 'Erro no registo.' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Credenciais inválidas.' });
        
        req.session.userId = user.id;
        res.json({ success: true, user });
    } catch (err) { res.status(500).json({ error: 'Erro no login.' }); }
});

app.post('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ user: null });
    const user = await dbGet('SELECT id, username, display_name, avatar, bio, status FROM users WHERE id = ?', [req.session.userId]);
    res.json({ user });
});

app.get('/api/servers', requireAuth, async (req, res) => res.json(await dbAll('SELECT * FROM servers')));
app.get('/api/servers/:serverId/channels', requireAuth, async (req, res) => res.json(await dbAll('SELECT * FROM channels WHERE server_id = ?', [req.params.serverId])));
app.get('/api/servers/:serverId/members', requireAuth, async (req, res) => res.json(await dbAll('SELECT id, username, display_name, avatar, status, bio FROM users ORDER BY display_name ASC')));
app.get('/api/users/:userId', requireAuth, async (req, res) => res.json(await dbGet('SELECT id, username, display_name, avatar, status, bio FROM users WHERE id = ?', [req.params.userId])));

app.get('/api/channels/:channelId/messages', requireAuth, async (req, res) => {
    const messages = await dbAll(`
        SELECT m.*, u.display_name, u.avatar 
        FROM messages m JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? ORDER BY m.created_at ASC LIMIT 150
    `, [req.params.channelId]);
    res.json(messages);
});

app.post('/api/profile', requireAuth, async (req, res) => {
    const { display_name, bio, status, avatar } = req.body;
    await dbRun('UPDATE users SET display_name = ?, bio = ?, status = ?, avatar = ? WHERE id = ?', [display_name, bio, status, avatar, req.session.userId]);
    res.json({ success: true });
});

// Upload de Ficheiros
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Nenhum ficheiro recebido.' });
    res.json({ url: `/uploads/${req.file.filename}`, type: req.file.mimetype, name: req.file.originalname });
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// --- SOCKET.IO ---
const onlineUsers = new Map();
io.on('connection', (socket) => {
    const session = socket.request.session;
    if (!session || !session.userId) return socket.disconnect();
    
    const userId = session.userId;
    onlineUsers.set(socket.id, userId);
    io.emit('user_status', { userId, status: 'Online' });

    socket.on('join_channel', (channelId) => {
        Array.from(socket.rooms).forEach(room => { if (room !== socket.id) socket.leave(room); });
        socket.join(channelId);
    });

    socket.on('send_message', async (data) => {
        try {
            const { channelId, content, fileUrl, fileType, fileName } = data;
            if ((!content || !content.trim()) && !fileUrl) return;

            const msgId = crypto.randomUUID();
            await dbRun('INSERT INTO messages (id, channel_id, user_id, content, file_url, file_type, file_name) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                [msgId, channelId, userId, content, fileUrl, fileType, fileName]);

            const user = await dbGet('SELECT display_name, avatar FROM users WHERE id = ?', [userId]);
            
            io.to(channelId).emit('new_message', {
                id: msgId, channel_id: channelId, user_id: userId, content,
                file_url: fileUrl, file_type: fileType, file_name: fileName,
                created_at: new Date().toISOString(),
                display_name: user.display_name, avatar: user.avatar
            });
        } catch (err) { console.error(err); }
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        if (!Array.from(onlineUsers.values()).includes(userId)) io.emit('user_status', { userId, status: 'Offline' });
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Servidor a correr na porta ${PORT}`));
