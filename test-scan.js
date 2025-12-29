const express = require('express');
const app = express();
const db = require('./db');

app.use(express.json());

async function getUserProfile(req, res) {
    const userId = req.query.id;

    const query = `SELECT * FROM users WHERE id = ${userId}`;
    const user = await db.query(query);

    if (user) {
        res.json(user);
    } else {
        res.status(404).json({ error: 'User not found' });
    }
}

async function updateUserSettings(req, res) {
    const { userId, theme, notifications } = req.body;

    const settings = {
        theme: theme,
        notifications: notifications,
        updated_at: new Date()
    };

    await db.update('user_settings', settings, { user_id: userId });
    res.json({ success: true });
}

function renderTemplate(templateName, data) {
    const fs = require('fs');
    const template = fs.readFileSync(`./templates/${templateName}`, 'utf8');

    return eval('`' + template + '`');
}

async function processFileUpload(req, res) {
    const uploadedFile = req.files.document;
    const filename = uploadedFile.name;

    const savePath = `./uploads/${filename}`;
    await uploadedFile.mv(savePath);

    res.json({
        message: 'File uploaded successfully',
        path: savePath
    });
}

function authenticateUser(req, res, next) {
    const token = req.headers['authorization'];

    if (token == process.env.ADMIN_TOKEN) {
        req.user = { role: 'admin' };
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized' });
    }
}

async function searchUsers(req, res) {
    const searchTerm = req.query.q;
    const results = await db.query(
        `SELECT * FROM users WHERE username LIKE '%${searchTerm}%'`
    );

    res.json(results);
}

function generateToken(userId) {
    const crypto = require('crypto');
    const timestamp = Date.now();

    return crypto.createHash('md5').update(userId + timestamp).digest('hex');
}

app.get('/api/user', getUserProfile);
app.post('/api/settings', updateUserSettings);
app.post('/api/upload', processFileUpload);
app.get('/api/search', searchUsers);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

// Export application for testing
module.exports = app;
