const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const JWT_SECRET = '9c84b1f92aee884e1f0505852779a77ec26e604026c27878929af0881740db8f';

const pool = new Pool({
    user: 'postgres',
    host: '127.0.0.1',
    database: 'auth_db',
    password: '270989',
    port: 5432,
});

// Middleware pour vérifier le token JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Route POST /users (Créer un utilisateur)
app.post('/users', async (req, res) => {
    const { firstName, lastName, email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4) RETURNING *',
            [firstName, lastName, email, hashedPassword]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route POST /login (Authentification)
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Invalid credentials' });

        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route GET /me (Obtenir les informations de l'utilisateur connecté)
app.get('/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Route PUT /user/{id} (Mettre à jour un utilisateur)
app.put('/user/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { firstName, lastName, email, password } = req.body;

    try {
        // Optionnel: hash le mot de passe si fourni
        const hashedPassword = password ? await bcrypt.hash(password, 10) : null;

        // Préparer la requête SQL avec les champs à mettre à jour
        const queryValues = [firstName, lastName, email];
        let queryText = 'UPDATE users SET first_name = $1, last_name = $2, email = $3';

        if (hashedPassword) {
            queryText += ', password = $4';
            queryValues.push(hashedPassword);
        }

        queryText += ' WHERE id = $5 RETURNING *';
        queryValues.push(id);

        const result = await pool.query(queryText, queryValues);

        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });

        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error updating user:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});


// Route DELETE /user/{id} (Supprimer un utilisateur)
app.delete('/user/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: 'User deleted' });
    } catch (err) {
        console.error('Error deleting user:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route GET /user/{id} (Obtenir un utilisateur)
app.get('/user/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.json(result.rows[0]);
    } catch (err) {
        console.error('Error fetching user:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Route GET /users (Obtenir tous les utilisateurs)
app.get('/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM users');
        res.json(result.rows);
    } catch (err) {
        console.error('Error fetching users:', err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Démarrer le serveur
app.listen(3000, () => {
    console.log('Server is running on port 3000');
});
