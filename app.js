const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const crypto = require('crypto');
const app = express();

// ========== VULNERABILIDAD 1: Hardcoded Secrets ==========
const API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const DB_PASSWORD = "admin123";
const JWT_SECRET = "mi-secreto-super-seguro-123";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";

// ========== VULNERABILIDAD 2: Uso de eval() ==========
app.get('/calculate', (req, res) => {
    const expression = req.query.exp;
    const result = eval(expression); // Peligroso: permite inyección de código
    res.send(`Resultado: ${result}`);
});

// ========== VULNERABILIDAD 3: Insecure Cookies ==========
app.get('/login', (req, res) => {
    res.cookie('session', 'user123', {
        // Falta HttpOnly, Secure y SameSite
    });
    res.cookie('admin', 'true', {
        httpOnly: false // Cookie accesible por JavaScript
    });
    res.send('Login exitoso');
});

// ========== VULNERABILIDAD 4: SQL Injection ==========
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DB_PASSWORD,
        database: 'test'
    });
    
    // Concatenación directa -> SQL Injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

// ========== VULNERABILIDAD 5: Path Traversal ==========
app.get('/read-file', (req, res) => {
    const filename = req.query.file;
    // Sin validación de path -> permite leer cualquier archivo
    fs.readFile('./files/' + filename, 'utf8', (err, data) => {
        if (err) {
            res.send('Error al leer archivo');
        } else {
            res.send(data);
        }
    });
});

// ========== VULNERABILIDAD 6: XSS (Cross-Site Scripting) ==========
app.get('/greet', (req, res) => {
    const name = req.query.name;
    // Respuesta sin sanitizar -> vulnerable a XSS
    res.send(`<h1>Hola ${name}</h1>`);
});

// ========== VULNERABILIDAD 7: Command Injection ==========
const { exec } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;
    // Ejecución directa de comandos del sistema
    exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
        if (error) {
            res.send(`Error: ${error.message}`);
            return;
        }
        res.send(`<pre>${stdout}</pre>`);
    });
});

// ========== VULNERABILIDAD 8: Criptografía Débil ==========
app.get('/encrypt', (req, res) => {
    const text = req.query.text;
    // MD5 es débil y no debe usarse para contraseñas
    const hash = crypto.createHash('md5').update(text).digest('hex');
    res.send(`Hash MD5: ${hash}`);
});

// ========== VULNERABILIDAD 9: Exposición de Información Sensible ==========
app.get('/debug', (req, res) => {
    // Exponer información del sistema
    res.json({
        node_version: process.version,
        env: process.env,
        db_password: DB_PASSWORD,
        api_key: API_KEY
    });
});

// ========== VULNERABILIDAD 10: Missing Security Headers ==========
app.get('/api/data', (req, res) => {
    // No se incluyen headers de seguridad como CORS, CSP, etc.
    res.json({ data: 'Información sensible', user: 'admin' });
});

// ========== VULNERABILIDAD 11: Weak Random Number Generation ==========
app.get('/generate-token', (req, res) => {
    // Math.random() no es criptográficamente seguro
    const token = Math.random().toString(36).substring(2);
    res.send(`Token generado: ${token}`);
});

// ========== VULNERABILIDAD 12: No Rate Limiting ==========
app.get('/login-attempt', (req, res) => {
    // Sin límite de intentos -> vulnerable a fuerza bruta
    res.send('Intento de login registrado');
});

// ========== VULNERABILIDAD 13: Deprecated Functions ==========
app.get('/old-function', (req, res) => {
    // Uso de función obsoleta
    const buffer = new Buffer('datos'); // Buffer() está deprecated
    res.send('Usando función obsoleta');
});

// ========== VULNERABILIDAD 14: Insecure Redirect ==========
app.get('/redirect', (req, res) => {
    const url = req.query.url;
    // Redirección sin validación -> Open Redirect
    res.redirect(url);
});

app.listen(3000, () => {
    console.log('Servidor corriendo en puerto 3000');
    console.log('⚠️ Este código contiene múltiples vulnerabilidades para práctica SAST');
});
