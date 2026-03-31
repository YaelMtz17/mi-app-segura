const express = require('express');
const mysql = require('mysql');
const app = express();

// VULNERABILIDAD 1: Hardcoded Secret
const API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
const DB_PASSWORD = "admin123";

// VULNERABILIDAD 2: Insecure Cookie
app.get('/login', (req, res) => {
    res.cookie('session', 'user123', {
        // Falta HttpOnly y Secure
    });
    res.send('Login exitoso');
});

// VULNERABILIDAD 3: SQL Injection
app.get('/user', (req, res) => {
    const userId = req.query.id;
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'root',
        password: DB_PASSWORD,
        database: 'test'
    });
    
    const query = "SELECT * FROM users WHERE id = " + userId;
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

app.listen(3000, () => {
    console.log('Servidor corriendo en puerto 3000');
});