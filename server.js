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
require('dotenv').config();

// Ensure data directory exists for SQLite
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize Application
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session Configuration
const sessionMiddleware = session({
    store: new SQLiteStore({ dir: './data', db: 'sessions.db' }),
    secret: process.env.SESSION_SECRET || 'fallback_secret_for_local_dev',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true } // 30 days
});
app.use(sessionMiddleware);

// Share session with Socket.IO
io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, next);
});

// Database Setup & Promisification wrapper
const db = new sqlite3.Database(path.join(dataDir, 'vynxgram.db'));
const dbRun = (sql, params = []) => new Promise((res, rej) => db.run(sql, params, function(err) { err ? rej(err) : res(this) }));
const dbGet = (sql, params = []) => new Promise((res, rej) => db.get(sql, params, (err, row) => err ? rej(err) : res(row)));
const dbAll = (sql, params = []) => new Promise((res, rej) => db.all(sql, params, (err, rows) => err ? rej(err) : res(rows)));

async function initDB() {
    await dbRun(`CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, display_name TEXT, 
        avatar TEXT, bio TEXT, status TEXT DEFAULT 'Online', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS servers (
        id TEXT PRIMARY KEY, name TEXT, icon TEXT, owner_id TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS channels (
        id TEXT PRIMARY KEY, server_id TEXT, name TEXT, type TEXT DEFAULT 'text', created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
    await dbRun(`CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY, channel_id TEXT, user_id TEXT, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Seed default Server and Channel if non-existent
    const globalServer = await dbGet("SELECT id FROM servers WHERE name = 'Global Community'");
    if (!globalServer) {
        const serverId = crypto.randomUUID();
        await dbRun("INSERT INTO servers (id, name, owner_id) VALUES (?, ?, ?)", [serverId, 'Global Community', 'system']);
        await dbRun("INSERT INTO channels (id, server_id, name) VALUES (?, ?, ?)", [crypto.randomUUID(), serverId, 'general']);
        await dbRun("INSERT INTO channels (id, server_id, name) VALUES (?, ?, ?)", [crypto.randomUUID(), serverId, 'introductions']);
    }
}
initDB().catch(console.error);

// Auth Middleware Guard
const requireAuth = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Unauthorized' });
    next();
};

// --- REST API ROUTES ---

// Auth Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password || password.length < 6) {
            return res.status(400).json({ error: 'Invalid username or password too short.' });
        }
        
        const existing = await dbGet('SELECT id FROM users WHERE username = ?', [username]);
        if (existing) return res.status(400).json({ error: 'Username already taken.' });

        const hash = await bcrypt.hash(password, 10);
        const id = crypto.randomUUID();
        const displayName = username.charAt(0).toUpperCase() + username.slice(1);
        
        await dbRun('INSERT INTO users (id, username, password_hash, display_name) VALUES (?, ?, ?, ?)', 
            [id, username, hash, displayName]);
        
        req.session.userId = id;
        res.json({ success: true, user: { id, username, display_name: displayName } });
    } catch (err) {
        res.status(500).json({ error: 'Server error during registration.' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await dbGet('SELECT * FROM users WHERE username = ?', [username]);
        
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: 'Invalid credentials.' });
        }
        
        req.session.userId = user.id;
        res.json({ success: true, user: { id: user.id, username: user.username, display_name: user.display_name, avatar: user.avatar, bio: user.bio, status: user.status } });
    } catch (err) {
        res.status(500).json({ error: 'Server error during login.' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ user: null });
    const user = await dbGet('SELECT id, username, display_name, avatar, bio, status FROM users WHERE id = ?', [req.session.userId]);
    res.json({ user });
});

// App Data Routes
app.get('/api/servers', requireAuth, async (req, res) => {
    const servers = await dbAll('SELECT * FROM servers ORDER BY created_at ASC');
    res.json(servers);
});

app.get('/api/servers/:serverId/channels', requireAuth, async (req, res) => {
    const channels = await dbAll('SELECT * FROM channels WHERE server_id = ? ORDER BY created_at ASC', [req.params.serverId]);
    res.json(channels);
});

app.get('/api/channels/:channelId/messages', requireAuth, async (req, res) => {
    const messages = await dbAll(`
        SELECT m.id, m.content, m.created_at, u.id as user_id, u.display_name, u.avatar 
        FROM messages m 
        JOIN users u ON m.user_id = u.id 
        WHERE m.channel_id = ? 
        ORDER BY m.created_at ASC 
        LIMIT 100
    `, [req.params.channelId]);
    res.json(messages);
});

// Profile Update
app.post('/api/profile', requireAuth, async (req, res) => {
    const { display_name, bio, status } = req.body;
    await dbRun('UPDATE users SET display_name = ?, bio = ?, status = ? WHERE id = ?', 
        [display_name, bio, status, req.session.userId]);
    res.json({ success: true });
});

// Serve Main Frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Index.html'));
});

// --- REAL-TIME WEB-SOCKETS ---
const onlineUsers = new Map(); // socket.id -> userId
const userStatusCache = new Set(); // set of userIds online

io.on('connection', (socket) => {
    const session = socket.request.session;
    if (!session || !session.userId) {
        return socket.disconnect();
    }

    const userId = session.userId;
    onlineUsers.set(socket.id, userId);
    userStatusCache.add(userId);
    
    // Broadcast status to everyone
    io.emit('user_status', { userId, status: 'Online' });

    socket.on('join_channel', (channelId) => {
        // Leave previous channels (except own ID for DMs)
        Array.from(socket.rooms).forEach(room => {
            if (room !== socket.id) socket.leave(room);
        });
        socket.join(channelId);
    });

    socket.on('send_message', async (data) => {
        try {
            const { channelId, content } = data;
            if (!content || !content.trim()) return;

            const msgId = crypto.randomUUID();
            await dbRun('INSERT INTO messages (id, channel_id, user_id, content) VALUES (?, ?, ?, ?)', 
                [msgId, channelId, userId, content]);

            const user = await dbGet('SELECT display_name, avatar FROM users WHERE id = ?', [userId]);
            
            // Broadcast to room
            io.to(channelId).emit('new_message', {
                id: msgId,
                channel_id: channelId,
                content: content,
                created_at: new Date().toISOString(),
                user_id: userId,
                display_name: user.display_name,
                avatar: user.avatar
            });
        } catch (err) {
            console.error('Message error:', err);
        }
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        // Check if user has other active tabs/sockets
        const isStillOnline = Array.from(onlineUsers.values()).includes(userId);
        if (!isStillOnline) {
            userStatusCache.delete(userId);
            io.emit('user_status', { userId, status: 'Offline' });
        }
    });
});

// Start Server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Vynxgram Server is running on port ${PORT}`);
});
