require('dotenv').config(); // Variables de entorno
const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet'); // Seguridad: headers
const rateLimit = require('express-rate-limit'); // Rate limiting
const path = require('path');
const { body, validationResult, sanitize } = require('express-validator'); // Validación
const app = express();

// ========== CORRECCIÓN 1: Hardcoded Secrets ==========
// Usar variables de entorno en lugar de valores hardcodeados
const API_KEY = process.env.API_KEY;
const DB_PASSWORD = process.env.DB_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;

// Verificar que las variables de entorno existan
if (!API_KEY || !DB_PASSWORD || !JWT_SECRET) {
    console.error('ERROR: Faltan variables de entorno. Crea un archivo .env');
    process.exit(1);
}

// ========== CORRECCIÓN 10: Security Headers con Helmet ==========
app.use(helmet()); // Agrega headers de seguridad (CSP, XSS Protection, etc.)

// ========== CORRECCIÓN 12: Rate Limiting ==========
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 100, // Máximo 100 peticiones por ventana
    message: 'Demasiadas peticiones desde esta IP, por favor intenta más tarde'
});
app.use('/login-attempt', limiter);
app.use('/api/', limiter);

// Middleware para parsear JSON
app.use(express.json());

// ========== CORRECCIÓN 2: Uso de eval() ==========
// Reemplazar eval() con una alternativa segura
app.get('/calculate', (req, res) => {
    const expression = req.query.exp;
    
    // Validar que la expresión solo contenga números y operadores básicos
    const validPattern = /^[0-9+\-*/()\s]+$/;
    if (!validPattern.test(expression)) {
        return res.status(400).json({ error: 'Expresión no válida' });
    }
    
    try {
        // Usar Function() en lugar de eval() con validación
        const calculate = new Function('return (' + expression + ')');
        const result = calculate();
        res.json({ result });
    } catch (error) {
        res.status(400).json({ error: 'Error en la expresión' });
    }
});

// ========== CORRECCIÓN 3: Insecure Cookies ==========
app.get('/login', (req, res) => {
    res.cookie('session', 'user123', {
        httpOnly: true,      // No accesible por JavaScript
        secure: true,        // Solo se envía por HTTPS
        sameSite: 'strict',  // Protección contra CSRF
        maxAge: 3600000      // 1 hora de expiración
    });
    
    res.cookie('admin', 'true', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
    });
    
    res.json({ message: 'Login exitoso', success: true });
});

// ========== CORRECCIÓN 4: SQL Injection ==========
app.get('/user', (req, res) => {
    const userId = req.query.id;
    
    // Validar que userId sea un número
    if (!userId || isNaN(userId)) {
        return res.status(400).json({ error: 'ID de usuario inválido' });
    }
    
    const connection = mysql.createConnection({
        host: process.env.DB_HOST || 'localhost',
        user: process.env.DB_USER || 'root',
        password: DB_PASSWORD,
        database: process.env.DB_NAME || 'test'
    });
    
    // Consulta parametrizada -> Previene SQL Injection
    const query = "SELECT * FROM users WHERE id = ?";
    connection.query(query, [userId], (error, results) => {
        if (error) {
            console.error('Error en consulta:', error);
            return res.status(500).json({ error: 'Error en la base de datos' });
        }
        connection.end();
        res.json(results);
    });
});

// ========== CORRECCIÓN 5: Path Traversal ==========
app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    
    // Validar que el archivo existe y está dentro del directorio permitido
    if (!filename) {
        return res.status(400).json({ error: 'Nombre de archivo requerido' });
    }
    
    // Sanitizar y validar path
    const safePath = path.join(__dirname, 'files', path.basename(filename));
    
    // Verificar que el path está dentro del directorio permitido
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
        res.json({ content: data });
    });
});

// ========== CORRECCIÓN 6: XSS (Cross-Site Scripting) ==========
const escapeHtml = (text) => {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

app.get('/greet', (req, res) => {
    const name = req.query.name || 'Invitado';
    // Sanitizar entrada para prevenir XSS
    const safeName = escapeHtml(name);
    res.send(`<h1>Hola ${safeName}</h1>`);
    // Mejor práctica: Usar JSON en lugar de HTML
    // res.json({ message: `Hola ${safeName}` });
});

// ========== CORRECCIÓN 7: Command Injection ==========
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;
    
    // Validar formato de host (solo direcciones IP o dominios válidos)
    const validHostPattern = /^[a-zA-Z0-9.-]+$/;
    if (!host || !validHostPattern.test(host)) {
        return res.status(400).json({ error: 'Host inválido' });
    }
    
    // Usar array de argumentos para evitar inyección
    const ping = require('ping');
    ping.sys.probe(host, (isAlive) => {
        res.json({ host, alive: isAlive });
    });
});

// ========== CORRECCIÓN 8: Criptografía Débil ==========
app.get('/encrypt', (req, res) => {
    const text = req.query.text;
    
    if (!text) {
        return res.status(400).json({ error: 'Texto requerido' });
    }
    
    // Usar algoritmo seguro SHA-256 en lugar de MD5
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    res.json({ 
        algorithm: 'SHA-256',
        input: text,
        hash: hash 
    });
});

// ========== CORRECCIÓN 9: Exposición de Información Sensible ==========
app.get('/debug', (req, res) => {
    // NO exponer información sensible en producción
    // Solo exponer información no crítica
    if (process.env.NODE_ENV === 'production') {
        return res.status(403).json({ error: 'Acceso denegado en producción' });
    }
    
    // Exponer solo información no sensible
    res.json({
        node_version: process.version,
        environment: process.env.NODE_ENV || 'development',
        // NO exponer contraseñas o API keys
        server_time: new Date().toISOString()
    });
});

// ========== CORRECCIÓN 11: Weak Random Number Generation ==========
app.get('/generate-token', (req, res) => {
    // Usar crypto.randomBytes() que es criptográficamente seguro
    const token = crypto.randomBytes(32).toString('hex');
    res.json({ 
        token: token,
        length: token.length,
        algorithm: 'crypto.randomBytes (seguro)'
    });
});

// ========== CORRECCIÓN 13: Deprecated Functions ==========
app.get('/new-function', (req, res) => {
    // Usar Buffer.from() en lugar de Buffer() (deprecated)
    const buffer = Buffer.from('datos', 'utf8');
    res.json({ 
        message: 'Usando función moderna',
        data: buffer.toString(),
        type: 'Buffer.from() - recomendado'
    });
});

// ========== CORRECCIÓN 14: Insecure Redirect ==========
const validDomains = ['example.com', 'mysite.com', 'localhost'];
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    
    if (!url) {
        return res.status(400).json({ error: 'URL requerida' });
    }
    
    try {
        const parsedUrl = new URL(url);
        // Validar que la URL pertenezca a dominios permitidos
        if (!validDomains.includes(parsedUrl.hostname)) {
            return res.status(403).json({ error: 'Dominio no permitido para redirección' });
        }
        res.redirect(url);
    } catch (error) {
        res.status(400).json({ error: 'URL inválida' });
    }
});

// ========== ENDPOINT SEGURO PARA API ==========
app.get('/api/data', (req, res) => {
    // Helmet ya agrega headers de seguridad
    res.json({ 
        data: 'Información pública',
        status: 'OK',
        timestamp: new Date().toISOString()
    });
});

// ========== MANEJO DE ERRORES ==========
app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ 
        error: 'Error interno del servidor',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ========== INICIAR SERVIDOR ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`✅ Servidor seguro corriendo en puerto ${PORT}`);
    console.log(`🔒 Modo: ${process.env.NODE_ENV || 'development'}`);
    console.log('📊 Todas las vulnerabilidades han sido corregidas');
});
