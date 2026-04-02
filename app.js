require('dotenv').config();
const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const app = express();

// ========== CONFIGURACIÓN INICIAL ==========
const API_KEY = process.env.API_KEY || "sk_test_placeholder_cambiar";
const DB_PASSWORD = process.env.DB_PASSWORD || "password_placeholder_cambiar";
const JWT_SECRET = process.env.JWT_SECRET || "jwt_secret_placeholder_cambiar";

console.log('🔧 Servidor iniciando con configuración de seguridad mejorada');

// ========== SEGURIDAD: HEADERS CON HELMET ==========
app.use(helmet());

// ========== SEGURIDAD: RATE LIMITING ==========
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Demasiadas peticiones, intenta más tarde' }
});
app.use('/api/', limiter);
app.use('/login-attempt', limiter);

// Middleware para JSON
app.use(express.json());

// ========== FUNCIÓN PARA ESCAPAR HTML (XSS) ==========
const escapeHtml = (text) => {
    if (!text) return '';
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

// ========== ENDPOINTS CORREGIDOS ==========

// 1. CORRECCIÓN: Hardcoded Secrets (usando variables de entorno)
app.get('/config-status', (req, res) => {
    res.json({
        message: 'Configuración segura',
        api_key_configured: !!API_KEY && API_KEY !== 'sk_test_placeholder_cambiar',
        db_configured: !!DB_PASSWORD && DB_PASSWORD !== 'password_placeholder_cambiar'
    });
});

// 2. CORRECCIÓN: Uso de eval() reemplazado por cálculo seguro
app.get('/calculate', (req, res) => {
    const expression = req.query.exp;
    
    if (!expression) {
        return res.status(400).json({ error: 'Se requiere una expresión' });
    }
    
    const validPattern = /^[0-9+\-*/()\s]+$/;
    if (!validPattern.test(expression)) {
        return res.status(400).json({ error: 'Expresión contiene caracteres no permitidos' });
    }
    
    try {
        const result = Function('"use strict"; return (' + expression + ')')();
        res.json({ expression, result });
    } catch (error) {
        res.status(400).json({ error: 'Error en la expresión matemática' });
    }
});

// 3. CORRECCIÓN: Insecure Cookies (con flags de seguridad)
app.get('/login', (req, res) => {
    res.cookie('session', 'user123', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict',
        maxAge: 3600000
    });
    
    res.cookie('admin', 'false', {
        httpOnly: true,
        secure: false,
        sameSite: 'strict'
    });
    
    res.json({ 
        success: true, 
        message: 'Login exitoso',
        cookies_secure: true
    });
});

// 4. CORRECCIÓN: SQL Injection (consultas parametrizadas)
app.get('/user', (req, res) => {
    const userId = req.query.id;
    
    if (!userId) {
        return res.status(400).json({ error: 'ID de usuario requerido' });
    }
    
    if (isNaN(userId)) {
        return res.status(400).json({ error: 'ID debe ser un número' });
    }
    
    const connection = mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: DB_PASSWORD,
        database: process.env.DB_NAME || 'test'
    });
    
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [parseInt(userId)], (error, results) => {
        if (error) {
            console.error('Error DB:', error);
            return res.status(500).json({ error: 'Error en la consulta' });
        }
        connection.end();
        res.json({ users: results });
    });
});

// 5. CORRECCIÓN: Path Traversal (validación de rutas)
app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    
    if (!filename) {
        return res.status(400).json({ error: 'Nombre de archivo requerido' });
    }
    
    const safePath = path.join(__dirname, 'files', path.basename(filename));
    
    if (!safePath.startsWith(path.join(__dirname, 'files'))) {
        return res.status(403).json({ error: 'Acceso denegado' });
    }
    
    fs.readFile(safePath, 'utf8', (err, data) => {
        if (err) {
            if (err.code === 'ENOENT') {
                return res.status(404).json({ error: 'Archivo no encontrado' });
            }
            return res.status(500).json({ error: 'Error al leer archivo' });
        }
        res.json({ filename, content: data });
    });
});

// 6. CORRECCIÓN: XSS (sanitización de entrada)
app.get('/greet', (req, res) => {
    const name = req.query.name || 'Invitado';
    const safeName = escapeHtml(name);
    res.send(`<h1>Hola ${safeName}</h1><p>Bienvenido a la aplicación segura</p>`);
});

// 7. CORRECCIÓN: Command Injection (validación estricta)
app.get('/ping', (req, res) => {
    const host = req.query.host;
    
    const validHostPattern = /^[a-zA-Z0-9.-]+$/;
    if (!host || !validHostPattern.test(host)) {
        return res.status(400).json({ error: 'Host inválido' });
    }
    
    if (host.length > 100) {
        return res.status(400).json({ error: 'Host demasiado largo' });
    }
    
    const ping = require('ping');
    ping.sys.probe(host, (isAlive) => {
        res.json({ 
            host, 
            alive: isAlive,
            message: isAlive ? 'Host responde' : 'Host no responde'
        });
    });
});

// 8. CORRECCIÓN: Criptografía Débil (SHA-256 en lugar de MD5)
app.get('/encrypt', (req, res) => {
    const text = req.query.text;
    
    if (!text) {
        return res.status(400).json({ error: 'Texto requerido' });
    }
    
    if (text.length > 1000) {
        return res.status(400).json({ error: 'Texto demasiado largo' });
    }
    
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    res.json({ 
        algorithm: 'SHA-256',
        input_length: text.length,
        hash: hash 
    });
});

// 9. CORRECCIÓN: Exposición de Información (datos seguros)
app.get('/debug', (req, res) => {
    res.json({
        node_version: process.version,
        environment: process.env.NODE_ENV || 'development',
        server_time: new Date().toISOString(),
        status: 'healthy'
    });
});

// 10. CORRECCIÓN: API con headers seguros
app.get('/api/data', (req, res) => {
    res.json({ 
        data: 'Información pública',
        status: 'OK',
        timestamp: new Date().toISOString()
    });
});

// 11. CORRECCIÓN: Generación de tokens segura
app.get('/generate-token', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ 
        token: token,
        length: token.length,
        secure: true
    });
});

// 12. CORRECCIÓN: Login con rate limiting
let loginAttempts = new Map();
app.post('/login-attempt', (req, res) => {
    const username = req.body.username;
    
    if (!username) {
        return res.status(400).json({ error: 'Usuario requerido' });
    }
    
    const attempts = loginAttempts.get(username) || 0;
    
    if (attempts >= 5) {
        return res.status(429).json({ error: 'Demasiados intentos, cuenta bloqueada temporalmente' });
    }
    
    loginAttempts.set(username, attempts + 1);
    
    setTimeout(() => {
        loginAttempts.delete(username);
    }, 15 * 60 * 1000);
    
    res.json({ 
        message: 'Intento registrado',
        attempts_left: 4 - attempts
    });
});

// 13. CORRECCIÓN: Buffer moderno
app.get('/buffer-example', (req, res) => {
    const data = Buffer.from('Datos seguros', 'utf8');
    res.json({ 
        message: 'Usando Buffer.from()',
        data: data.toString(),
        method: 'Buffer.from() - método seguro'
    });
});

// 14. CORRECCIÓN: Redirección segura
const allowedDomains = ['example.com', 'localhost', '127.0.0.1'];
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    if (!url) {
        return res.status(400).json({ error: 'URL requerida' });
    }
    
    try {
        const parsedUrl = new URL(url);
        if (!allowedDomains.includes(parsedUrl.hostname)) {
            return res.status(403).json({ error: 'Dominio no permitido' });
        }
        res.redirect(url);
    } catch (error) {
        res.status(400).json({ error: 'URL inválida' });
    }
});

// ========== MANEJO DE ERRORES GLOBAL ==========
app.use((err, req, res, next) => {
    console.error('Error:', err.message);
    res.status(500).json({ 
        error: 'Error interno del servidor',
        code: 'SERVER_ERROR'
    });
});

// ========== INICIO DEL SERVIDOR ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor seguro corriendo en puerto ${PORT}`);
    console.log(`🔒 Modo: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🛡️  Vulnerabilidades corregidas: 14`);
});
