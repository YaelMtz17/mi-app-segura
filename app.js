// ========== DEPENDENCIAS ==========
const express = require('express');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

// ========== INICIALIZACIÓN ==========
const app = express();

// ========== MIDDLEWARE DE SEGURIDAD ==========
app.use(helmet());
app.use(express.json());

// ========== RATE LIMITING ==========
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests' }
});
app.use(limiter);

// ========== FUNCIÓN DE SANITIZACIÓN ==========
function sanitizeInput(input) {
    if (typeof input !== 'string') return '';
    return input.replace(/[<>]/g, '');
}

// ========== ENDPOINTS SEGUROS ==========

// 1. Endpoint seguro con validación
app.get('/api/status', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '2.0.0'
    });
});

// 2. Cálculo seguro (sin eval)
app.get('/api/calculate', (req, res) => {
    const expression = req.query.exp;
    
    if (!expression) {
        return res.status(400).json({ error: 'Expression required' });
    }
    
    const validPattern = /^[0-9+\-*/()\s]+$/;
    if (!validPattern.test(expression)) {
        return res.status(400).json({ error: 'Invalid expression' });
    }
    
    try {
        const result = Function('return (' + expression + ')')();
        res.json({ result });
    } catch {
        res.status(400).json({ error: 'Invalid expression' });
    }
});

// 3. Login con cookies seguras
app.post('/api/login', (req, res) => {
    const { username } = req.body;
    
    if (!username || typeof username !== 'string') {
        return res.status(400).json({ error: 'Username required' });
    }
    
    const safeUsername = sanitizeInput(username);
    
    res.cookie('session', crypto.randomBytes(32).toString('hex'), {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 3600000
    });
    
    res.json({
        success: true,
        message: 'Login successful',
        user: safeUsername
    });
});

// 4. Obtener usuario (simulado, sin SQL)
app.get('/api/user/:id', (req, res) => {
    const userId = parseInt(req.params.id);
    
    if (isNaN(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const users = [
        { id: 1, name: 'Admin' },
        { id: 2, name: 'User' }
    ];
    
    const user = users.find(u => u.id === userId);
    
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
});

// 5. Saludo seguro (sin XSS)
app.get('/api/greet', (req, res) => {
    let name = req.query.name || 'Guest';
    
    if (typeof name !== 'string') {
        name = 'Guest';
    }
    
    const safeName = sanitizeInput(name);
    
    res.json({
        message: `Hello ${safeName}`,
        timestamp: new Date().toISOString()
    });
});

// 6. Ping seguro (sin command injection)
app.get('/api/ping', async (req, res) => {
    const host = req.query.host;
    
    if (!host || typeof host !== 'string') {
        return res.status(400).json({ error: 'Host required' });
    }
    
    const validHostPattern = /^[a-zA-Z0-9.-]+$/;
    if (!validHostPattern.test(host) || host.length > 100) {
        return res.status(400).json({ error: 'Invalid host' });
    }
    
    res.json({
        host,
        status: 'simulated',
        message: 'Ping simulation - secure'
    });
});

// 7. Encriptación segura (SHA-256)
app.get('/api/encrypt', (req, res) => {
    const text = req.query.text;
    
    if (!text || typeof text !== 'string') {
        return res.status(400).json({ error: 'Text required' });
    }
    
    if (text.length > 1000) {
        return res.status(400).json({ error: 'Text too long' });
    }
    
    const hash = crypto.createHash('sha256').update(text).digest('hex');
    
    res.json({
        algorithm: 'SHA-256',
        hash
    });
});

// 8. Generar token seguro
app.get('/api/token', (req, res) => {
    const token = crypto.randomBytes(32).toString('hex');
    
    res.json({
        token,
        length: token.length,
        secure: true
    });
});

// 9. Información segura (sin exposición)
app.get('/api/info', (req, res) => {
    res.json({
        name: 'Secure API',
        version: '2.0.0',
        status: 'operational'
    });
});

// 10. Redirección segura
app.get('/api/redirect', (req, res) => {
    const destination = req.query.to;
    const allowedDestinations = ['home', 'profile', 'settings'];
    
    if (!destination || !allowedDestinations.includes(destination)) {
        return res.status(400).json({ error: 'Invalid destination' });
    }
    
    res.json({
        message: `Redirect to ${destination}`,
        redirect: `/api/${destination}`
    });
});

// 11. Health check
app.get('/health', (req, res) => {
    res.status(200).json({ status: 'healthy' });
});

// 12. Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: 'Secure API',
        endpoints: ['/api/status', '/health', '/api/info'],
        version: '2.0.0'
    });
});

// ========== MANEJO DE ERRORES ==========
app.use((err, req, res, next) => {
    console.error(err.message);
    res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// ========== INICIO DEL SERVIDOR ==========
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Secure server running on port ${PORT}`);
    console.log(`Mode: ${process.env.NODE_ENV || 'development'}`);
});
