const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// CORS setup for React frontend
app.use(cors({
    origin: process.env.NODE_ENV === 'production' ? false : ['http://localhost:3000'],
    credentials: true
}));

// Serve static files from public directory (for production build)
app.use(express.static(path.join(__dirname, 'client/build')));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});
app.use(limiter);

// WebSocket setup
const io = new Server(server, {
    cors: { origin: "*" },
    pingTimeout: 60000,
    pingInterval: 25000
});

// Database setup with connection callback
const dbPath = path.join(__dirname, 'users.db');
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Database connection error:', err.message);
    } else {
        console.log('Connected to SQLite database');
        // Create users table
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                hashedPassword TEXT,
                name TEXT,
                school TEXT,
                program TEXT,
                gender TEXT,
                lookingFor TEXT,
                studentStatus TEXT,
                createdAt TEXT,
                verificationStatus TEXT,
                studentIdPhotoPath TEXT,
                studentIdPhotoBackPath TEXT,
                selfiePhotoPath TEXT,
                inCall INTEGER DEFAULT 0,
                loveQuestionType TEXT,
                loveQuestionAnswer TEXT
            )`, (err) => {
            if (err) {
                console.error('Table creation error:', err.message);
            } else {
                console.log('Users table ready');
            }
        });
        // Add friends table with mode
        db.run(`CREATE TABLE IF NOT EXISTS friends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1 TEXT,
            user2 TEXT,
            mode TEXT,
            createdAt TEXT
        )`, (err) => {
            if (err) console.error('Friends table creation error:', err.message);
        });
        // Add rejections table for swipe lefts
        db.run(`CREATE TABLE IF NOT EXISTS rejections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rejector TEXT,
            rejected TEXT,
            createdAt TEXT
        )`, (err) => {
            if (err) console.error('Rejections table creation error:', err.message);
        });
        // Ensure loveQuestionType and loveQuestionAnswer columns exist
        db.get("PRAGMA table_info(users)", (err, columns) => {
            if (err) return console.error('PRAGMA error:', err.message);
            const colNames = Array.isArray(columns) ? columns.map(c => c.name) : [];
            if (!colNames.includes('loveQuestionType')) {
                db.run('ALTER TABLE users ADD COLUMN loveQuestionType TEXT', err => {
                    if (err) console.error('Add column loveQuestionType error:', err.message);
                });
            }
            if (!colNames.includes('loveQuestionAnswer')) {
                db.run('ALTER TABLE users ADD COLUMN loveQuestionAnswer TEXT', err => {
                    if (err) console.error('Add column loveQuestionAnswer error:', err.message);
                });
            }
        });
    }
});

// Debug endpoint to check database contents
app.get('/debug/users', (req, res) => {
    db.all('SELECT id, email, name, createdAt FROM users', (err, rows) => {
        if (err) {
            console.error('DEBUG endpoint error:', err);
            return res.status(500).send('Database error');
        }
        res.json(rows);
    });
});

// Canadian university domains
const canadianUniversityDomains = new Set([
    'utoronto.ca', 'mail.utoronto.ca', 'uoft.ca',
    'ubc.ca', 'student.ubc.ca', 'alumni.ubc.ca',
    'mcgill.ca', 'mail.mcgill.ca',
    'yorku.ca', 'my.yorku.ca',
    'uwaterloo.ca', 'edu.uwaterloo.ca',
    'queensu.ca', 'ualberta.ca', 'ucalgary.ca', 'umanitoba.ca', 'usask.ca',
    'mun.ca', 'unb.ca', 'dal.ca', 'dal.mail.ca', 'uottawa.ca', 'carleton.ca',
    'ryerson.ca', 'torontomu.ca', 'concordia.ca', 'uqam.ca', 'sfu.ca', 'uvic.ca',
    'unbc.ca', 'uregina.ca', 'upei.ca', 'stfx.ca', 'uwindsor.ca', 'brocku.ca',
    'guelph.ca', 'lakeheadu.ca', 'laurentian.ca', 'nipissingu.ca',
    'ontariotechu.ca', 'trentu.ca', 'wlu.ca', 'uwo.ca', 'macewan.ca',
    'mtroyal.ca', 'viu.ca', 'kpu.ca', 'langara.ca', 'umontreal.ca',
    'usherbrooke.ca', 'ulaval.ca', 'etsmtl.ca', 'polymtl.ca', 'hec.ca',
    'senecacollege.ca', 'georgebrown.ca', 'humber.ca', 'centennialcollege.ca',
    'fanshawec.ca', 'mohawkcollege.ca', 'sheridancollege.ca', 'conestogac.on.ca',
    'sait.ca', 'nait.ca', 'bcit.ca'
]);

// Helper functions
function isCanadianStudentEmail(email) {
    const emailLower = email.toLowerCase();
    for (const domain of canadianUniversityDomains) {
        if (emailLower.endsWith('@' + domain)) {
            return { isStudent: true, type: 'verified', institution: domain };
        }
    }
    return { isStudent: false, type: 'unknown', institution: null };
}

function validatePassword(password) {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumbers = /\d/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

    if (password.length < minLength) return { valid: false, message: 'Password must be at least 8 characters long' };
    if (!hasUpperCase) return { valid: false, message: 'Password must contain at least one uppercase letter' };
    if (!hasLowerCase) return { valid: false, message: 'Password must contain at least one lowercase letter' };
    if (!hasNumbers) return { valid: false, message: 'Password must contain at least one number' };
    if (!hasSpecialChar) return { valid: false, message: 'Password must contain at least one special character' };

    return { valid: true };
}

function validateEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Data structures
const users = {};
const queues = {
    love: [],
    rival: [],
    fun: []
};
const activeCalls = {};
const swipes = {}; // { roomId: { [socketId]: 'left'|'right' } }

// Add rival school mapping and program compatibility
const rivalSchools = {
    'University of Toronto': ['University of Waterloo', 'York University'],
    'University of Waterloo': ['University of Toronto', 'McGill University'],
    'McGill University': ['University of Waterloo', 'University of British Columbia'],
    'University of British Columbia': ['McGill University', 'University of Alberta'],
    'York University': ['University of Toronto'],
    'University of Alberta': ['University of British Columbia', 'University of Calgary'],
    'University of Calgary': ['University of Alberta'],
    // Add more as needed
};

function areRivals(schoolA, schoolB) {
    return (rivalSchools[schoolA] && rivalSchools[schoolA].includes(schoolB)) ||
           (rivalSchools[schoolB] && rivalSchools[schoolB].includes(schoolA));
}

const programCompat = {
    'computer science': ['health science', 'business', 'engineering', 'arts'],
    'health science': ['computer science', 'business', 'arts'],
    'business': ['computer science', 'health science', 'arts'],
    'engineering': ['computer science', 'arts'],
    'arts': ['computer science', 'health science', 'business', 'engineering'],
    // Add more as needed
};

function areProgramsCompatible(progA, progB) {
    progA = progA.toLowerCase();
    progB = progB.toLowerCase();
    if (programCompat[progA] && programCompat[progA].includes(progB)) return true;
    if (programCompat[progB] && programCompat[progB].includes(progA)) return true;
    return false;
}

function genderCompatible(userA, userB) {
    // userA.lookingFor must match userB.gender and vice versa
    if (userA.lookingFor === 'any' || userB.gender === 'prefer_not_to_say') return true;
    if (userA.lookingFor === userB.gender) return true;
    return false;
}

function mutualGenderCompatible(userA, userB) {
    return genderCompatible(userA, userB) && genderCompatible(userB, userA);
}

// Socket.io connection handler
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Initialize user state
    users[socket.id] = {
        authenticated: false
    };

    // Registration handler - FIXED
    socket.on('register', async (userData) => {
        try {
            const { name, school, program, email, password, gender, lookingFor } = userData;
            
            if (!name || !school || !program || !email || !password || !gender || !lookingFor) {
                return socket.emit('register-error', 'All fields are required');
            }

            const emailLower = email.toLowerCase();
            console.log(`Registering user: ${emailLower}`);

            // Validate email format
            if (!validateEmail(emailLower)) {
                return socket.emit('register-error', 'Invalid email format');
            }

            // Check password strength
            const passwordValidation = validatePassword(password);
            if (!passwordValidation.valid) {
                return socket.emit('register-error', passwordValidation.message);
            }

            db.get('SELECT * FROM users WHERE email = ?', [emailLower], async (err, row) => {
                if (err) {
                    console.error('SELECT error:', err.message);
                    return socket.emit('register-error', 'Database error');
                }
                
                if (row) {
                    return socket.emit('email-exists', 'This email is already registered. Please login instead.');
                }

                try {
                    const hashedPassword = await bcrypt.hash(password, 12);
                    const statusInfo = isCanadianStudentEmail(emailLower);
                    const studentStatus = JSON.stringify(statusInfo);
                    const createdAt = new Date().toISOString();

                    db.run(
                        `INSERT INTO users (
                            email, 
                            hashedPassword, 
                            name, 
                            school, 
                            program, 
                            gender,
                            lookingFor,
                            studentStatus, 
                            createdAt
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                        [
                            emailLower,
                            hashedPassword,
                            name.trim(),
                            school.trim(),
                            program?.trim() || '',
                            gender,
                            lookingFor,
                            studentStatus,
                            createdAt
                        ],
                        function (insertErr) {
                            if (insertErr) {
                                console.error('INSERT error:', insertErr.message);
                                return socket.emit('register-error', 'Failed to create user');
                            }
                            
                            console.log(`User registered: ${emailLower} (ID: ${this.lastID})`);
                            
                            users[socket.id] = {
                                ...users[socket.id],
                                email: emailLower,
                                name: name.trim(),
                                school: school.trim(),
                                program: program?.trim() || '',
                                gender,
                                lookingFor,
                                studentStatus: statusInfo,
                                authenticated: true
                            };
                            
                            socket.emit('register-success', {
                                message: 'Registration successful!',
                                user: users[socket.id]
                            });
                        }
                    );
                } catch (hashErr) {
                    console.error('Password hash error:', hashErr);
                    socket.emit('register-error', 'Server error during registration');
                }
            });
        } catch (error) {
            console.error('Registration process error:', error);
            socket.emit('register-error', 'Server error during registration');
        }
    });

    // Login handler
    socket.on('login', async ({ email, password }) => {
        try {
            if (!email || !password) {
                return socket.emit('login-error', 'Email and password are required');
            }

            const emailLower = email.toLowerCase();

            db.get('SELECT * FROM users WHERE email = ?', [emailLower], async (err, row) => {
                if (err) {
                    console.error('DB error:', err);
                    return socket.emit('login-error', 'Database error');
                }
                if (!row) {
                    return socket.emit('login-error', 'Invalid email or password');
                }

                const passwordMatch = await bcrypt.compare(password, row.hashedPassword);
                if (!passwordMatch) {
                    return socket.emit('login-error', 'Invalid email or password');
                }

                users[socket.id] = {
                    ...users[socket.id],
                    email: row.email,
                    name: row.name,
                    school: row.school,
                    program: row.program || '',
                    gender: row.gender,
                    lookingFor: row.lookingFor,
                    studentStatus: JSON.parse(row.studentStatus),
                    authenticated: true
                };

                socket.emit('login-success', users[socket.id]);
            });
        } catch (error) {
            console.error('Login error:', error);
            socket.emit('login-error', 'Server error during login');
        }
    });

    // Mode selection handler
    socket.on('select-mode', (modeData) => {
        if (!users[socket.id]?.authenticated) {
            socket.emit('error', { message: 'Please log in first' });
            return;
        }
        let mode = modeData;
        if (typeof modeData === 'object' && modeData.mode === 'love') {
            // Store love question answer in session and DB
            users[socket.id].mode = 'love';
            users[socket.id].loveQuestionType = modeData.loveQuestionType;
            users[socket.id].loveQuestionAnswer = modeData.loveQuestionAnswer;
            db.run('UPDATE users SET loveQuestionType = ?, loveQuestionAnswer = ? WHERE email = ?',
                [modeData.loveQuestionType, modeData.loveQuestionAnswer, users[socket.id].email],
                err => { if (err) console.error('DB update love question error:', err.message); });
            mode = 'love';
        } else if (typeof modeData === 'string') {
            users[socket.id].mode = modeData;
            mode = modeData;
        }
        if (!queues[mode].includes(socket.id)) {
            queues[mode].push(socket.id);
            attemptPairing(mode);
        }
    });

    // WebRTC signaling handler
    socket.on('signal', (data) => {
        if (!users[socket.id]?.authenticated) {
            socket.emit('error', { message: 'Please log in first' });
            return;
        }
        io.to(data.target).emit('signal', {
            sender: socket.id,
            signal: data.signal
        });
    });

    // Call management handlers
    socket.on('end-call', () => endCallForUser(socket.id));
    socket.on('cancel-search', () => removeFromQueues(socket.id));
    socket.on('media-error', (data) => handleMediaError(socket.id, data.error));

    // Cleanup on disconnect
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        endCallForUser(socket.id);
        removeFromQueues(socket.id);
        delete users[socket.id];
    });

    // Swipe handler
    socket.on('swipe', ({ direction, partnerId, roomId }) => {
        if (!roomId || !partnerId) return;
        if (!swipes[roomId]) swipes[roomId] = {};
        swipes[roomId][socket.id] = direction;
        // If left, end call for both and record rejection
        if (direction === 'left') {
            const userA = users[socket.id];
            const userB = users[partnerId];
            if (userA && userB) {
                recordRejection(userA.email, userB.email);
            }
            io.to(partnerId).emit('call-ended', { reason: 'Partner swiped left' });
            io.to(socket.id).emit('call-ended', { reason: 'You swiped left' });
            delete activeCalls[socket.id];
            delete activeCalls[partnerId];
            delete swipes[roomId];
            return;
        }
        // If both right, match!
        if (swipes[roomId][socket.id] === 'right' && swipes[roomId][partnerId] === 'right') {
            io.to(socket.id).emit('match');
            io.to(partnerId).emit('match');
            // Store friendship in DB (by email) and mode
            const userA = users[socket.id];
            const userB = users[partnerId];
            if (userA && userB) {
                const mode = userA.mode || userB.mode || 'fun';
                db.run('INSERT INTO friends (user1, user2, mode, createdAt) VALUES (?, ?, ?, ?)',
                    [userA.email, userB.email, mode, new Date().toISOString()],
                    err => { if (err) console.error('Friend insert error:', err.message); });
            }
            delete swipes[roomId];
        }
    });

    // Chat relay for matched users
    socket.on('chat-message', ({ to, message }) => {
        if (activeCalls[socket.id] === to) {
            io.to(to).emit('chat-message', { from: socket.id, message });
        }
    });

    // Add get-friends event
    socket.on('get-friends', (cb) => {
        const user = users[socket.id];
        if (!user || !user.email) return cb({ error: 'Not logged in' });
        db.all('SELECT * FROM friends WHERE user1 = ? OR user2 = ?', [user.email, user.email], (err, rows) => {
            if (err) return cb({ error: 'DB error' });
            const grouped = { love: [], rival: [], fun: [] };
            rows.forEach(row => {
                const friendEmail = row.user1 === user.email ? row.user2 : row.user1;
                grouped[row.mode || 'fun'].push({ email: friendEmail, mode: row.mode, createdAt: row.createdAt });
            });
            cb({ friends: grouped });
        });
    });

    // Helper functions
    function endCallForUser(userId) {
        const partnerId = activeCalls[userId];
        if (partnerId) {
            // Set inCall=0 for both users
            const userA = users[userId];
            const userB = users[partnerId];
            if (userA) db.run('UPDATE users SET inCall = 0 WHERE email = ?', [userA.email]);
            if (userB) db.run('UPDATE users SET inCall = 0 WHERE email = ?', [userB.email]);
            io.to(partnerId).emit('call-ended', { 
                reason: 'Partner ended the call',
                partnerName: users[userId]?.name || 'Partner'
            });
            delete activeCalls[userId];
            delete activeCalls[partnerId];
        }
    }

    function removeFromQueues(socketId) {
        Object.keys(queues).forEach(mode => {
            queues[mode] = queues[mode].filter(id => id !== socketId);
        });
    }

    function handleMediaError(userId, error) {
        console.error(`Media error for user ${userId}: ${error}`);
        removeFromQueues(userId);
        if (activeCalls[userId]) {
            endCallForUser(userId);
        }
    }

    function attemptPairing(mode) {
        const queue = queues[mode];
        // Opposite majors mapping (broad, mixed-up)
        const oppositeMajors = {
            'engineering': ['arts', 'education', 'psychology', 'literature', 'law'],
            'arts': ['engineering', 'computer science', 'math', 'business', 'science'],
            'computer science': ['health science', 'education', 'arts', 'law', 'biology'],
            'health science': ['computer science', 'math', 'business', 'arts', 'engineering'],
            'business': ['science', 'arts', 'engineering', 'math', 'psychology'],
            'science': ['business', 'arts', 'law', 'education', 'engineering'],
            'math': ['arts', 'education', 'health science', 'law', 'business'],
            'education': ['engineering', 'computer science', 'math', 'science'],
            'law': ['computer science', 'science', 'engineering', 'math'],
            'psychology': ['engineering', 'business', 'math', 'computer science'],
            'literature': ['engineering', 'math', 'computer science', 'science'],
            'biology': ['computer science', 'business', 'law'],
            // Add more as needed
        };
        function majorsAreOpposite(a, b) {
            a = (a||'').toLowerCase(); b = (b||'').toLowerCase();
            return (oppositeMajors[a] && oppositeMajors[a].includes(b)) || (oppositeMajors[b] && oppositeMajors[b].includes(a));
        }
        // Love mode: only use program compatibility + gender
        if (mode === 'love') {
            for (let i = 0; i < queue.length; i++) {
                for (let j = i + 1; j < queue.length; j++) {
                    const idA = queue[i];
                    const idB = queue[j];
                    const userA = users[idA];
                    const userB = users[idB];
                    if (!userA || !userB) continue;
                    let compatible = areProgramsCompatible(userA.program, userB.program) && mutualGenderCompatible(userA, userB);
                    if (compatible) {
                        haveRejectedEachOther(userA.email, userB.email, (rejected) => {
                            if (rejected) return;
                            queues[mode] = queue.filter(id => id !== idA && id !== idB);
                            activeCalls[idA] = idB;
                            activeCalls[idB] = idA;
                            const roomId = uuidv4();
                            db.run('UPDATE users SET inCall = 1 WHERE email = ?', [userA.email]);
                            db.run('UPDATE users SET inCall = 1 WHERE email = ?', [userB.email]);
                            io.to(idA).emit('partner-found', {
                                partnerId: idB,
                                partnerName: userB.name || 'Anonymous',
                                roomId
                            });
                            io.to(idB).emit('partner-found', {
                                partnerId: idA,
                                partnerName: userA.name || 'Anonymous',
                                roomId
                            });
                        });
                        return;
                    }
                }
            }
            return;
        }
        // Rival/fun: original logic
        for (let i = 0; i < queue.length; i++) {
            for (let j = i + 1; j < queue.length; j++) {
                const idA = queue[i];
                const idB = queue[j];
                const userA = users[idA];
                const userB = users[idB];
                if (!userA || !userB) continue;
                let compatible = false;
                if (mode === 'rival') {
                    compatible = areRivals(userA.school, userB.school);
                } else if (mode === 'fun') {
                    compatible = true;
                }
                if (compatible) {
                    haveRejectedEachOther(userA.email, userB.email, (rejected) => {
                        if (rejected) return;
                        queues[mode] = queue.filter(id => id !== idA && id !== idB);
                        activeCalls[idA] = idB;
                        activeCalls[idB] = idA;
                        const roomId = uuidv4();
                        db.run('UPDATE users SET inCall = 1 WHERE email = ?', [userA.email]);
                        db.run('UPDATE users SET inCall = 1 WHERE email = ?', [userB.email]);
                        io.to(idA).emit('partner-found', {
                            partnerId: idB,
                            partnerName: userB.name || 'Anonymous',
                            roomId
                        });
                        io.to(idB).emit('partner-found', {
                            partnerId: idA,
                            partnerName: userA.name || 'Anonymous',
                            roomId
                        });
                    });
                    return;
                }
            }
        }
    }

    function recordRejection(rejector, rejected) {
        db.run('INSERT INTO rejections (rejector, rejected, createdAt) VALUES (?, ?, ?)',
            [rejector, rejected, new Date().toISOString()],
            err => { if (err) console.error('Rejection insert error:', err.message); });
    }

    function haveRejectedEachOther(emailA, emailB, cb) {
        db.get('SELECT 1 FROM rejections WHERE (rejector = ? AND rejected = ?) OR (rejector = ? AND rejected = ?)',
            [emailA, emailB, emailB, emailA],
            (err, row) => {
                if (err) { console.error('Rejection check error:', err.message); cb(false); return; }
                cb(!!row);
            }
        );
    }
});

// Express route for registration with file upload
app.post('/register', multer({ dest: path.join(__dirname, 'uploads') }).fields([
    { name: 'studentIdPhotoFront', maxCount: 1 },
    { name: 'studentIdPhotoBack', maxCount: 1 },
    { name: 'selfiePhoto', maxCount: 1 }
]), async (req, res) => {
    try {
        const { name, school, program, email, password, gender, lookingFor } = req.body;
        const studentIdPhotoFront = req.files['studentIdPhotoFront']?.[0];
        const studentIdPhotoBack = req.files['studentIdPhotoBack']?.[0];
        const selfiePhoto = req.files['selfiePhoto']?.[0];
        if (!name || !school || !program || !email || !password || !gender || !lookingFor || !studentIdPhotoFront || !studentIdPhotoBack || !selfiePhoto) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        const emailLower = email.toLowerCase();
        db.get('SELECT * FROM users WHERE email = ?', [emailLower], async (err, row) => {
            if (err) return res.status(500).json({ error: 'Database error' });
            if (row) return res.status(400).json({ error: 'This email is already registered. Please login instead.' });
            try {
                const hashedPassword = await bcrypt.hash(password, 12);
                const statusInfo = isCanadianStudentEmail(emailLower); // You may want to update this for global
                const studentStatus = JSON.stringify(statusInfo);
                const createdAt = new Date().toISOString();
                const verificationStatus = 'pending';
                db.run(
                    `INSERT INTO users (
                        email, hashedPassword, name, school, program, gender, lookingFor, studentStatus, createdAt, verificationStatus, studentIdPhotoPath, studentIdPhotoBackPath, selfiePhotoPath
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        emailLower,
                        hashedPassword,
                        name.trim(),
                        school.trim(),
                        program?.trim() || '',
                        gender,
                        lookingFor,
                        studentStatus,
                        createdAt,
                        verificationStatus,
                        studentIdPhotoFront.path,
                        studentIdPhotoBack.path,
                        selfiePhoto.path
                    ],
                    function (insertErr) {
                        if (insertErr) {
                            return res.status(500).json({ error: 'Failed to create user' });
                        }
                        return res.json({ message: 'Registration successful! Pending manual verification.', user: { email: emailLower, name, verificationStatus } });
                    }
                );
            } catch (hashErr) {
                return res.status(500).json({ error: 'Server error during registration' });
            }
        });
    } catch (error) {
        return res.status(500).json({ error: 'Server error during registration' });
    }
});

// Set your admin secret in an environment variable, e.g. ADMIN_SECRET=yourpassword node server.js
const ADMIN_SECRET = process.env.ADMIN_SECRET || 'changeme';
function requireAdminSecret(req, res, next) {
    const secret = req.headers['x-admin-secret'];
    if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'Forbidden' });
    next();
}

// Admin endpoint to get all pending users
app.get('/admin/pending-users', requireAdminSecret, (req, res) => {
    db.all('SELECT id, email, name, school, studentIdPhotoPath, studentIdPhotoBackPath, selfiePhotoPath FROM users WHERE verificationStatus = ?', ['pending'], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ users: rows });
    });
});

// Admin endpoint to approve a user
app.post('/admin/approve-user', requireAdminSecret, express.json(), (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    db.run('UPDATE users SET verificationStatus = ? WHERE email = ?', ['verified', email], function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        // Send email notification (sketch config)
        const transporter = nodemailer.createTransport({
            host: 'smtp.example.com', // TODO: Replace with real SMTP
            port: 587,
            secure: false,
            auth: {
                user: 'your@email.com',
                pass: 'yourpassword'
            }
        });
        const mailOptions = {
            from: 'no-reply@uniconnect.com',
            to: email,
            subject: 'Your UniConnect account is verified!',
            text: 'Congratulations! Your student verification has been approved. You can now use all features.'
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(200).json({ message: 'User approved, but email failed to send.' });
            }
            res.json({ message: 'User approved and email sent.' });
        });
    });
});

// Admin endpoint to reject a user
app.post('/admin/reject-user', requireAdminSecret, express.json(), (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    db.run('UPDATE users SET verificationStatus = ? WHERE email = ?', ['rejected', email], function (err) {
        if (err) return res.status(500).json({ error: 'DB error' });
        // Send rejection email
        const transporter = nodemailer.createTransport({
            host: 'smtp.example.com', // TODO: Replace with real SMTP
            port: 587,
            secure: false,
            auth: {
                user: 'your@email.com',
                pass: 'yourpassword'
            }
        });
        const mailOptions = {
            from: 'no-reply@uniconnect.com',
            to: email,
            subject: 'Your UniConnect verification was rejected',
            text: 'Sorry, your student verification was not approved. Please contact support if you believe this is a mistake.'
        };
        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                return res.status(200).json({ message: 'User rejected, but email failed to send.' });
            }
            res.json({ message: 'User rejected and email sent.' });
        });
    });
});

// Handle all other routes by serving index.html
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the app at http://localhost:${PORT}`);
    console.log(`Database path: ${dbPath}`);
    console.log(`Debug endpoint: http://localhost:${PORT}/debug/users`);
});