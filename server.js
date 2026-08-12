const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();

// Garantir que a diretoria de uploads existe
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Inicializar a Aplicação
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*', methods: ['GET', 'POST'] } });

// Middlewares
app.use(express.json({ limit: '1gb' }));
app.use(express.urlencoded({ extended: true, limit: '1gb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'))); // Servir ficheiros estáticos

// Configuração do Multer (Upload de até 1GB)
const storage = multer.diskStorage({
    destination: function (req, file, cb) { cb(null, 'uploads/'); },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage, limits: { fileSize: 1024 * 1024 * 1024 } }); // 1GB limit

// Configuração do MongoDB
const MONGO_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/vynxgram';

mongoose.connect(MONGO_URI).then(async () => {
    console.log('✅ Conectado ao MongoDB Permanente!');
    
    // Criar o Servidor Global padrão se não existir
    const globalServer = await ServerModel.findOne({ name: 'Global Community' });
    if (!globalServer) {
        const newServer = await ServerModel.create({ name: 'Global Community', owner_id: 'system' });
        await ChannelModel.create({ server_id: newServer._id, name: 'geral' });
        await ChannelModel.create({ server_id: newServer._id, name: 'apresentações' });
    }
}).catch(err => console.error('❌ Erro no MongoDB:', err));

// Schemas do MongoDB
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password_hash: String,
    display_name: String,
    avatar: String,
    bio: String,
    status: { type: String, default: 'Online' }
}, { timestamps: true });
const UserModel = mongoose.model('User', UserSchema);

const ServerSchema = new mongoose.Schema({
    name: String, owner_id: String, icon: String
}, { timestamps: true });
const ServerModel = mongoose.model('Server', ServerSchema);

const ChannelSchema = new mongoose.Schema({
    server_id: mongoose.Schema.Types.ObjectId, name: String, type: { type: String, default: 'text' }
}, { timestamps: true });
const ChannelModel = mongoose.model('Channel', ChannelSchema);

const MessageSchema = new mongoose.Schema({
    channel_id: mongoose.Schema.Types.ObjectId,
    user_id: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    content: String,
    fileUrl: String,
    fileType: String,
    fileName: String
}, { timestamps: true });
const MessageModel = mongoose.model('Message', MessageSchema);

// Configuração de Sessão (Salva no MongoDB!)
const sessionMiddleware = session({
    store: MongoStore.create({ mongoUrl: MONGO_URI }),
    secret: process.env.SESSION_SECRET || 'fallback_secret_for_local_dev',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000, httpOnly: true }
});
app.use(sessionMiddleware);
io.use((socket, next) => { sessionMiddleware(socket.request, {}, next); });

const requireAuth = (req, res, next) => {
    if (!req.session.userId) return res.status(401).json({ error: 'Não autorizado' });
    next();
};

// --- ROTAS DA API ---

app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password || password.length < 6) return res.status(400).json({ error: 'Dados inválidos.' });
        
        const existing = await UserModel.findOne({ username });
        if (existing) return res.status(400).json({ error: 'Nome de utilizador já em uso.' });

        const hash = await bcrypt.hash(password, 10);
        const displayName = username.charAt(0).toUpperCase() + username.slice(1);
        
        const user = await UserModel.create({ username, password_hash: hash, display_name: displayName });
        req.session.userId = user._id;
        res.json({ success: true, user });
    } catch (err) { res.status(500).json({ error: 'Erro no servidor.' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await UserModel.findOne({ username });
        if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'Credenciais inválidas.' });
        
        req.session.userId = user._id;
        res.json({ success: true, user });
    } catch (err) { res.status(500).json({ error: 'Erro no login.' }); }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', async (req, res) => {
    if (!req.session.userId) return res.json({ user: null });
    const user = await UserModel.findById(req.session.userId);
    res.json({ user });
});

app.get('/api/servers', requireAuth, async (req, res) => {
    const servers = await ServerModel.find().sort('createdAt');
    res.json(servers);
});

app.get('/api/servers/:serverId/channels', requireAuth, async (req, res) => {
    const channels = await ChannelModel.find({ server_id: req.params.serverId }).sort('createdAt');
    res.json(channels);
});

app.get('/api/channels/:channelId/messages', requireAuth, async (req, res) => {
    const messages = await MessageModel.find({ channel_id: req.params.channelId })
        .populate('user_id', 'display_name avatar')
        .sort('createdAt')
        .limit(150);
    res.json(messages);
});

app.get('/api/servers/:serverId/members', requireAuth, async (req, res) => {
    const members = await UserModel.find().select('username display_name avatar status bio').sort('display_name');
    res.json(members);
});

app.get('/api/users/:userId', requireAuth, async (req, res) => {
    const user = await UserModel.findById(req.params.userId).select('-password_hash');
    res.json(user);
});

app.post('/api/profile', requireAuth, async (req, res) => {
    const { display_name, bio, status, avatar } = req.body;
    await UserModel.findByIdAndUpdate(req.session.userId, { display_name, bio, status, avatar });
    res.json({ success: true });
});

// Upload de Arquivos
app.post('/api/upload', requireAuth, upload.single('file'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Nenhum ficheiro enviado.' });
    
    // Retorna a URL e os metadados
    const fileUrl = `/uploads/${req.file.filename}`;
    const fileType = req.file.mimetype;
    res.json({ url: fileUrl, type: fileType, name: req.file.originalname });
});

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

// --- WEB-SOCKETS ---
const onlineUsers = new Map();
const userStatusCache = new Set();

io.on('connection', (socket) => {
    const session = socket.request.session;
    if (!session || !session.userId) return socket.disconnect();

    const userId = session.userId;
    onlineUsers.set(socket.id, userId);
    userStatusCache.add(userId);
    io.emit('user_status', { userId, status: 'Online' });

    socket.on('join_channel', (channelId) => {
        Array.from(socket.rooms).forEach(room => { if (room !== socket.id) socket.leave(room); });
        socket.join(channelId);
    });

    socket.on('send_message', async (data) => {
        try {
            const { channelId, content, fileUrl, fileType, fileName } = data;
            if ((!content || !content.trim()) && !fileUrl) return;

            const user = await UserModel.findById(userId);
            const msg = await MessageModel.create({
                channel_id: channelId, user_id: userId, content, fileUrl, fileType, fileName
            });

            io.to(channelId).emit('new_message', {
                _id: msg._id, channel_id: channelId, content: msg.content,
                fileUrl: msg.fileUrl, fileType: msg.fileType, fileName: msg.fileName,
                createdAt: msg.createdAt,
                user_id: user._id, display_name: user.display_name, avatar: user.avatar
            });
        } catch (err) { console.error('Erro de mensagem:', err); }
    });

    socket.on('disconnect', () => {
        onlineUsers.delete(socket.id);
        if (!Array.from(onlineUsers.values()).includes(userId)) {
            userStatusCache.delete(userId);
            io.emit('user_status', { userId, status: 'Offline' });
        }
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Servidor a correr na porta ${PORT}`));
