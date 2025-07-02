const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcrypt');
const path = require('path');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const fs = require('fs');
const nodemailer = require('nodemailer');
const cors = require('cors');
const { Pool } = require('pg');

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
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

console.log('Connected to Neon/Postgres database');

// Table creation (async)
(async () => {
    await pool.query(`CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        schoolEmail TEXT UNIQUE,
        firstName TEXT,
        lastName TEXT,
        password TEXT,
        school TEXT,
        program TEXT,
        gender TEXT,
        lookingFor TEXT,
        studentIdPhotoPath TEXT,
        studentIdPhotoBackPath TEXT,
        selfiePhotoPath TEXT,
        verificationStatus TEXT DEFAULT 'pending',
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        inCall BOOLEAN DEFAULT FALSE,
        loveQuestionType TEXT,
        loveQuestionAnswer TEXT
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS friends (
        id SERIAL PRIMARY KEY,
        user1 TEXT,
        user2 TEXT,
        mode TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    await pool.query(`CREATE TABLE IF NOT EXISTS rejections (
        id SERIAL PRIMARY KEY,
        rejector TEXT,
        rejected TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`);
    console.log('Tables ensured in Neon/Postgres');
})();

// Debug endpoint to check database contents
app.get('/debug/users', (req, res) => {
    pool.query('SELECT id, schoolEmail, firstName, lastName, createdAt FROM users', (err, result) => {
        if (err) {
            console.error('DEBUG endpoint error:', err);
            return res.status(500).send('Database error');
        }
        res.json(result.rows);
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
io.on('connection', async (socket) => {
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

            const result = await pool.query('SELECT * FROM users WHERE schoolEmail = $1', [emailLower]);
            if (result.rows.length > 0) {
                return socket.emit('email-exists', 'This email is already registered. Please login instead.');
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 12);
                const statusInfo = await isCanadianStudentEmail(emailLower);
                const studentStatus = JSON.stringify(statusInfo);
                const createdAt = new Date().toISOString();

                await pool.query(`
                    INSERT INTO users (
                        schoolEmail, 
                        password, 
                        name, 
                        school, 
                        program, 
                        gender,
                        lookingFor,
                        studentStatus, 
                        createdAt
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
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
                    ]);

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
            } catch (hashErr) {
                console.error('Password hash error:', hashErr);
                socket.emit('register-error', 'Server error during registration');
            }
        } catch (error) {
            console.error('Registration process error:', error);
            socket.emit('register-error', 'Server error during registration');
        }
    });

    // Login handler
    socket.on('login', async ({ schoolEmail, password }) => {
        try {
            if (!schoolEmail || !password) {
                return socket.emit('login-error', 'Email and password are required');
            }

            const emailLower = schoolEmail.toLowerCase();

            const result = await pool.query('SELECT * FROM users WHERE schoolEmail = $1', [emailLower]);
            if (result.rows.length === 0) {
                return socket.emit('login-error', 'Invalid email or password');
            }

            const user = result.rows[0];

            if (user.verificationStatus !== 'verified') {
                return socket.emit('login-error', 'Account not yet verified. Please wait for admin approval.');
            }

            const passwordMatch = await bcrypt.compare(password, user.password);
            if (!passwordMatch) {
                return socket.emit('login-error', 'Invalid email or password');
            }

            users[socket.id] = {
                ...users[socket.id],
                schoolEmail: user.schoolEmail,
                firstName: user.firstName,
                lastName: user.lastName,
                name: `${user.firstName} ${user.lastName}`,
                school: user.school,
                program: user.program || '',
                gender: user.gender,
                lookingFor: user.lookingFor,
                studentStatus: JSON.parse(user.studentStatus),
                authenticated: true
            };

            socket.emit('login-success', users[socket.id]);
        } catch (error) {
            console.error('Login error:', error);
            socket.emit('login-error', 'Server error during login');
        }
    });

    // Mode selection handler
    socket.on('select-mode', async (modeData) => {
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
            await pool.query('UPDATE users SET loveQuestionType = $1, loveQuestionAnswer = $2 WHERE schoolEmail = $3',
                [modeData.loveQuestionType, modeData.loveQuestionAnswer, users[socket.id].schoolEmail]);
            mode = 'love';
        } else if (typeof modeData === 'string') {
            users[socket.id].mode = modeData;
            mode = modeData;
        }
        if (!queues[mode].includes(socket.id)) {
            queues[mode].push(socket.id);
            await attemptPairing(mode);
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
                recordRejection(userA.schoolEmail, userB.schoolEmail);
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
                await pool.query('INSERT INTO friends (user1, user2, mode, createdAt) VALUES ($1, $2, $3, $4)',
                    [userA.schoolEmail, userB.schoolEmail, mode, new Date().toISOString()]);
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
        if (!user || !user.schoolEmail) return cb({ error: 'Not logged in' });
        pool.query('SELECT * FROM friends WHERE user1 = $1 OR user2 = $1', [user.schoolEmail], async (err, result) => {
            if (err) return cb({ error: 'DB error' });
            const grouped = { love: [], rival: [], fun: [] };
            result.rows.forEach(row => {
                const friendEmail = row.user1 === user.schoolEmail ? row.user2 : row.user1;
                grouped[row.mode || 'fun'].push({ email: friendEmail, mode: row.mode, createdAt: row.createdAt });
            });
            cb({ friends: grouped });
        });
    });

    // Helper functions
    async function endCallForUser(userId) {
        const partnerId = activeCalls[userId];
        if (partnerId) {
            // Set inCall=0 for both users
            const userA = users[userId];
            const userB = users[partnerId];
            if (userA) await pool.query('UPDATE users SET inCall = FALSE WHERE schoolEmail = $1', [userA.schoolEmail]);
            if (userB) await pool.query('UPDATE users SET inCall = FALSE WHERE schoolEmail = $1', [userB.schoolEmail]);
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

    async function attemptPairing(mode) {
        const queue = queues[mode];
        
        // Love Mode: match random people from the same school
        if (mode === 'love') {
            for (let i = 0; i < queue.length; i++) {
                for (let j = i + 1; j < queue.length; j++) {
                    const idA = queue[i];
                    const idB = queue[j];
                    const userA = users[idA];
                    const userB = users[idB];
                    if (!userA || !userB) continue;
                    
                    // Same school and gender compatible
                    let compatible = userA.school === userB.school && mutualGenderCompatible(userA, userB);
                    
                    if (compatible) {
                        haveRejectedEachOther(userA.schoolEmail, userB.schoolEmail, (rejected) => {
                            if (rejected) return;
                            queues[mode] = queue.filter(id => id !== idA && id !== idB);
                            activeCalls[idA] = idB;
                            activeCalls[idB] = idA;
                            const roomId = uuidv4();
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userA.schoolEmail]);
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userB.schoolEmail]);
                            
                            // Create friendship record
                            const friendData = {
                                user1: userA.schoolEmail,
                                user2: userB.schoolEmail,
                                mode: 'love',
                                createdAt: new Date().toISOString()
                            };
                            await pool.query('INSERT INTO friends (user1, user2, mode, createdAt) VALUES ($1, $2, $3, $4)',
                                [friendData.user1, friendData.user2, friendData.mode, friendData.createdAt]);
                            
                            io.to(idA).emit('partner-found', {
                                partnerId: idB,
                                partnerName: `${userB.firstName} ${userB.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                            io.to(idB).emit('partner-found', {
                                partnerId: idA,
                                partnerName: `${userA.firstName} ${userA.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                        });
                        return;
                    }
                }
            }
            return;
        }
        
        // Rivals Mode: match students from other schools only
        if (mode === 'rival') {
            for (let i = 0; i < queue.length; i++) {
                for (let j = i + 1; j < queue.length; j++) {
                    const idA = queue[i];
                    const idB = queue[j];
                    const userA = users[idA];
                    const userB = users[idB];
                    if (!userA || !userB) continue;
                    
                    // Different schools
                    let compatible = userA.school !== userB.school;
                    
                    if (compatible) {
                        haveRejectedEachOther(userA.schoolEmail, userB.schoolEmail, (rejected) => {
                            if (rejected) return;
                            queues[mode] = queue.filter(id => id !== idA && id !== idB);
                            activeCalls[idA] = idB;
                            activeCalls[idB] = idA;
                            const roomId = uuidv4();
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userA.schoolEmail]);
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userB.schoolEmail]);
                            
                            // Create friendship record
                            const friendData = {
                                user1: userA.schoolEmail,
                                user2: userB.schoolEmail,
                                mode: 'rival',
                                createdAt: new Date().toISOString()
                            };
                            await pool.query('INSERT INTO friends (user1, user2, mode, createdAt) VALUES ($1, $2, $3, $4)',
                                [friendData.user1, friendData.user2, friendData.mode, friendData.createdAt]);
                            
                            io.to(idA).emit('partner-found', {
                                partnerId: idB,
                                partnerName: `${userB.firstName} ${userB.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                            io.to(idB).emit('partner-found', {
                                partnerId: idA,
                                partnerName: `${userA.firstName} ${userA.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                        });
                        return;
                    }
                }
            }
            return;
        }
        
        // Shits and Giggles Mode: match random people from any school
        if (mode === 'fun') {
            for (let i = 0; i < queue.length; i++) {
                for (let j = i + 1; j < queue.length; j++) {
                    const idA = queue[i];
                    const idB = queue[j];
                    const userA = users[idA];
                    const userB = users[idB];
                    if (!userA || !userB) continue;
                    
                    // Any school is compatible
                    let compatible = true;
                    
                    if (compatible) {
                        haveRejectedEachOther(userA.schoolEmail, userB.schoolEmail, (rejected) => {
                            if (rejected) return;
                            queues[mode] = queue.filter(id => id !== idA && id !== idB);
                            activeCalls[idA] = idB;
                            activeCalls[idB] = idA;
                            const roomId = uuidv4();
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userA.schoolEmail]);
                            await pool.query('UPDATE users SET inCall = TRUE WHERE schoolEmail = $1', [userB.schoolEmail]);
                            
                            // Create friendship record
                            const friendData = {
                                user1: userA.schoolEmail,
                                user2: userB.schoolEmail,
                                mode: 'fun',
                                createdAt: new Date().toISOString()
                            };
                            await pool.query('INSERT INTO friends (user1, user2, mode, createdAt) VALUES ($1, $2, $3, $4)',
                                [friendData.user1, friendData.user2, friendData.mode, friendData.createdAt]);
                            
                            io.to(idA).emit('partner-found', {
                                partnerId: idB,
                                partnerName: `${userB.firstName} ${userB.lastName}` || 'Anonymous',
                                name: `${userB.firstName} ${userB.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                            io.to(idB).emit('partner-found', {
                                partnerId: idA,
                                partnerName: `${userA.firstName} ${userA.lastName}` || 'Anonymous',
                                name: `${userA.firstName} ${userA.lastName}` || 'Anonymous',
                                roomId,
                                mode
                            });
                        });
                        return;
                    }
                }
            }
            return;
        }
    }

    async function recordRejection(rejector, rejected) {
        await pool.query('INSERT INTO rejections (rejector, rejected, createdAt) VALUES ($1, $2, $3)',
            [rejector, rejected, new Date().toISOString()]);
    }

    function haveRejectedEachOther(schoolEmailA, schoolEmailB, cb) {
        pool.query('SELECT 1 FROM rejections WHERE (rejector = $1 AND rejected = $2) OR (rejector = $2 AND rejected = $1)',
            [schoolEmailA, schoolEmailB],
            (err, result) => {
                if (err) { console.error('Rejection check error:', err.message); cb(false); return; }
                cb(result.rows.length > 0);
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
        const { firstName, lastName, schoolEmail, school, program, password, gender, lookingFor } = req.body;
        const studentIdPhotoFront = req.files['studentIdPhotoFront']?.[0];
        const studentIdPhotoBack = req.files['studentIdPhotoBack']?.[0];
        const selfiePhoto = req.files['selfiePhoto']?.[0];
        
        if (!firstName || !lastName || !schoolEmail || !school || !program || !password || !gender || !lookingFor || !studentIdPhotoFront || !studentIdPhotoBack || !selfiePhoto) {
            return res.status(400).json({ error: 'All fields are required' });
        }
        
        const emailLower = schoolEmail.toLowerCase();
        
        // Validate school email format
        const emailValidation = await isCanadianStudentEmail(emailLower);
        if (!emailValidation.isStudent) {
            return res.status(400).json({ error: 'Please use a valid school email address' });
        }
        
        const result = await pool.query('SELECT * FROM users WHERE schoolEmail = $1', [emailLower]);
        if (result.rows.length > 0) return res.status(400).json({ error: 'This email is already registered. Please login instead.' });
        
        try {
            const hashedPassword = await bcrypt.hash(password, 12);
            const studentStatus = JSON.stringify(emailValidation);
            const createdAt = new Date().toISOString();
            const verificationStatus = 'pending';
            
            await pool.query(`
                INSERT INTO users (
                    schoolEmail, hashedPassword, firstName, lastName, school, program, gender, lookingFor, studentStatus, createdAt, verificationStatus, studentIdPhotoPath, studentIdPhotoBackPath, selfiePhotoPath
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
                [
                    emailLower,
                    hashedPassword,
                    firstName.trim(),
                    lastName.trim(),
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
                ]);

            return res.json({ 
                message: 'Registration successful! Pending manual verification.', 
                user: { 
                    email: emailLower, 
                    name: `${firstName} ${lastName}`, 
                    verificationStatus 
                } 
            });
        } catch (hashErr) {
            return res.status(500).json({ error: 'Server error during registration' });
        }
    } catch (error) {
        return res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login endpoint
app.post('/login', express.json(), async (req, res) => {
    try {
        const { schoolEmail, password } = req.body;
        
        if (!schoolEmail || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const emailLower = schoolEmail.toLowerCase();
        
        const result = await pool.query('SELECT * FROM users WHERE schoolEmail = $1', [emailLower]);
        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        const user = result.rows[0];

        if (user.verificationStatus !== 'verified') {
            return res.status(401).json({ error: 'Account not yet verified. Please wait for admin approval.' });
        }

        try {
            const isValidPassword = await bcrypt.compare(password, user.password);
            
            if (!isValidPassword) {
                return res.status(401).json({ error: 'Invalid email or password' });
            }

            // Return user data (excluding sensitive info)
            const userData = {
                schoolEmail: user.schoolEmail,
                firstName: user.firstName,
                lastName: user.lastName,
                name: `${user.firstName} ${user.lastName}`,
                school: user.school,
                program: user.program,
                gender: user.gender,
                lookingFor: user.lookingFor,
                verificationStatus: user.verificationStatus
            };

            res.json({ user: userData });
        } catch (hashErr) {
            return res.status(500).json({ error: 'Server error during login' });
        }
    } catch (error) {
        return res.status(500).json({ error: 'Server error during login' });
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
    pool.query('SELECT id, schoolEmail, firstName, lastName, school, studentIdPhotoPath, studentIdPhotoBackPath, selfiePhotoPath FROM users WHERE verificationStatus = $1', ['pending'], (err, result) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json({ users: result.rows });
    });
});

// Admin endpoint to approve a user
app.post('/admin/approve-user', requireAdminSecret, express.json(), (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'User ID required' });
    
    // First get the user's email
    pool.query('SELECT schoolEmail FROM users WHERE id = $1', [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        
        const userEmail = result.rows[0].schoolEmail;
        
        pool.query('UPDATE users SET verificationStatus = $1 WHERE id = $2', ['verified', id], (err) => {
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
                to: userEmail,
                subject: 'Your Hey stranger account is verified!',
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
});

// Admin endpoint to reject a user
app.post('/admin/reject-user', requireAdminSecret, express.json(), (req, res) => {
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'User ID required' });
    
    // First get the user's email
    pool.query('SELECT schoolEmail FROM users WHERE id = $1', [id], (err, result) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        
        const userEmail = result.rows[0].schoolEmail;
        
        pool.query('UPDATE users SET verificationStatus = $1 WHERE id = $2', ['rejected', id], (err) => {
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
                to: userEmail,
                subject: 'Your Hey stranger verification was rejected',
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
});

// Get friends by mode
app.get('/friends', (req, res) => {
    const { email } = req.query;
    if (!email) {
        return res.status(400).json({ error: 'Email required' });
    }

    pool.query(`
        SELECT 
            f.mode,
            CASE 
                WHEN f.user1 = $1 THEN f.user2 
                ELSE f.user1 
            END as friendEmail,
            u.firstName,
            u.lastName,
            u.school
        FROM friends f
        JOIN users u ON (
            CASE 
                WHEN f.user1 = $1 THEN f.user2 
                ELSE f.user1 
            END = u.schoolEmail
        )
        WHERE (f.user1 = $1 OR f.user2 = $1)
        AND u.verificationStatus = 'verified'
        ORDER BY f.createdAt DESC
    `, [email], (err, result) => {
        if (err) {
            console.error('Friends query error:', err);
            return res.status(500).json({ error: 'Database error' });
        }

        // Group by mode
        const friendsByMode = {
            love: [],
            rival: [],
            fun: []
        };

        result.rows.forEach(row => {
            const friend = {
                email: row.friendEmail,
                name: `${row.firstName} ${row.lastName}`,
                school: row.school,
                mode: row.mode
            };
            
            if (friendsByMode[row.mode]) {
                friendsByMode[row.mode].push(friend);
            }
        });

        res.json(friendsByMode);
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
    console.log(`Database path: ${process.env.DATABASE_URL}`);
    console.log(`Debug endpoint: http://localhost:${PORT}/debug/users`);
});