// Modules

import { Server } from "socket.io";
import { createServer } from "http";
import { randomUUID, randomInt } from "crypto";
import { spawn } from "child_process";
import { createRequire } from "module";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import express from "express";
import "dotenv/config";
import pg from "pg";
import argon2 from "argon2";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { OAuth2Client } from "google-auth-library";
import { Chess } from "chess.js";
import helmet from "helmet";
import { rateLimit } from "express-rate-limit";

const { Pool } = pg;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

// Variables

const app = express();
const server = createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;
const STARTING_TIME = 10 * 60 * 1000;
const ELO_K = 32;
const RECONNECT_GRACE_MS = 30 * 1000;

const TIME_CONTROLS = {
    bullet1: { label: "1+0 Bullet", initialMs: 60 * 1000, incrementMs: 0 },
    blitz3: { label: "3+0 Blitz", initialMs: 3 * 60 * 1000, incrementMs: 0 },
    blitz32: { label: "3+2 Blitz", initialMs: 3 * 60 * 1000, incrementMs: 2 * 1000 },
    blitz5: { label: "5+0 Blitz", initialMs: 5 * 60 * 1000, incrementMs: 0 },
    rapid10: { label: "10+0 Rapid", initialMs: 10 * 60 * 1000, incrementMs: 0 },
    rapid1510: { label: "15+10 Rapid", initialMs: 15 * 60 * 1000, incrementMs: 10 * 1000 }
};

const USERNAME_CHANGE_COOLDOWN =
    7 * 24 * 60 * 60 * 1000;

const AVATAR_KEYS = new Set([
    "knight",
    "rook",
    "bishop",
    "queen",
    "king",
    "pawn",
    "bolt",
    "crown"
]);

const BOT_CONFIGS = {
    rookie500: {
        name: "Beginner",
        rating: 500,
        skillLevel: 0,
        thinkMs: 80,
        randomChance: 0.72,
        stockfishRequired: false
    },
    club1000: {
        name: "Casual",
        rating: 1000,
        skillLevel: 2,
        thinkMs: 110,
        randomChance: 0.28,
        stockfishRequired: false
    },
    tactician1500: {
        name: "Challenger",
        rating: 1500,
        eloLimit: 1500,
        thinkMs: 420,
        randomChance: 0,
        stockfishRequired: true,
        engineFlavor: "lite"
    },
    master2000: {
        name: "Expert",
        rating: 2000,
        eloLimit: 2000,
        thinkMs: 750,
        randomChance: 0,
        stockfishRequired: true,
        engineFlavor: "lite"
    },
    grandmaster2500: {
        name: "Grandmaster",
        rating: 2500,
        eloLimit: 2500,
        thinkMs: 1300,
        randomChance: 0,
        stockfishRequired: true,
        engineFlavor: "lite"
    },
    elite3000: {
        name: "Elite",
        rating: 3000,
        skillLevel: 20,
        thinkMs: 2200,
        randomChance: 0,
        stockfishRequired: true,
        engineFlavor: "lite"
    }
};

const GOOGLE_CLIENT_ID =
    process.env.GOOGLE_CLIENT_ID ||
    "544555583922-6ga00tnd4m312vt3qfb8ts5htuhvklum.apps.googleusercontent.com";

const googleClient =
    new OAuth2Client(GOOGLE_CLIENT_ID);

const waitingPlayers = new Map();

const games = new Map();
const privateWaiting = new Map();

app.set("trust proxy", 1);
app.disable("x-powered-by");

if (!process.env.DATABASE_URL) {
    throw new Error(
        "DATABASE_URL is required."
    );
}

if (
    process.env.NODE_ENV === "production" &&
    (
        !process.env.SESSION_SECRET ||
        process.env.SESSION_SECRET.length < 32
    )
) {
    throw new Error(
        "SESSION_SECRET must be at least 32 characters in production."
    );
}

app.use(
    helmet({
        crossOriginEmbedderPolicy: false,
        crossOriginOpenerPolicy: {
            policy: "same-origin-allow-popups"
        },
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "https://accounts.google.com"
                ],
                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://accounts.google.com"
                ],
                imgSrc: [
                    "'self'",
                    "data:",
                    "https://flagcdn.com",
                    "https://*.googleusercontent.com"
                ],
                connectSrc: [
                    "'self'",
                    "https://accounts.google.com"
                ],
                frameSrc: [
                    "https://accounts.google.com"
                ],
                objectSrc: ["'none'"],
                baseUri: ["'self'"],
                formAction: ["'self'"],
                upgradeInsecureRequests:
                    process.env.NODE_ENV === "production"
                        ? []
                        : null
            }
        }
    })
);

app.use(
    express.json({
        limit: "16kb",
        strict: true
    })
);

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 180,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many requests. Please slow down."
    }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    skipSuccessfulRequests: true,
    message: {
        error: "Too many login attempts. Try again later."
    }
});

const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    limit: 8,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many accounts created from this connection. Try again later."
    }
});

const accountLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 30,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many account changes. Try again later."
    }
});

const socialActionLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "Too many friend actions. Wait a few seconds and try again."
    }
});

const socialMessageLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 45,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: {
        error: "You are sending messages too quickly."
    }
});

app.use("/api", apiLimiter);

// Database

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === "test"
        ? false
        : { rejectUnauthorized: false }
});

const PostgreSQLStore =
    connectPgSimple(session);

const sessionMiddleware = session({
    name: "pulse.sid",

    store: new PostgreSQLStore({
        pool,
        createTableIfMissing: true
    }),

    secret:
        process.env.SESSION_SECRET ||
        "pulse-chess-development-secret-change-me",

    resave: false,
    saveUninitialized: false,
    rolling: true,

    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure:
            process.env.NODE_ENV ===
            "production",
        maxAge:
            7 * 24 * 60 * 60 * 1000
    }
});

app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

// Database Setup

async function initializeDatabase() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username VARCHAR(20) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT,
                google_id TEXT,
                rating INTEGER NOT NULL DEFAULT 1200,
                wins INTEGER NOT NULL DEFAULT 0,
                losses INTEGER NOT NULL DEFAULT 0,
                draws INTEGER NOT NULL DEFAULT 0,
                country_code CHAR(2),
                avatar_key VARCHAR(24) NOT NULL DEFAULT 'knight',
                profile_bio VARCHAR(120) NOT NULL DEFAULT '',
                username_changed_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS email_verifications (
                email VARCHAR(255) PRIMARY KEY,
                username VARCHAR(20) NOT NULL,
                password_hash TEXT NOT NULL,
                country_code CHAR(2),
                code_hash TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        await pool.query(`
            ALTER TABLE users
            ALTER COLUMN password_hash DROP NOT NULL
        `);

        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS google_id TEXT
        `);

        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS country_code CHAR(2)
        `);

        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS avatar_key VARCHAR(24)
            NOT NULL DEFAULT 'knight'
        `);

        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS profile_bio VARCHAR(120)
            NOT NULL DEFAULT ''
        `);

        await pool.query(`
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS username_changed_at TIMESTAMPTZ
        `);

        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS
            users_google_id_unique
            ON users (google_id)
            WHERE google_id IS NOT NULL
        `);

        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS
            users_username_lower_unique
            ON users (LOWER(username))
        `);

        await pool.query(`
            CREATE UNIQUE INDEX IF NOT EXISTS
            users_email_lower_unique
            ON users (LOWER(email))
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS matches (
                id BIGSERIAL PRIMARY KEY,
                white_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                black_user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                winner_color VARCHAR(5),
                reason VARCHAR(40) NOT NULL,
                rated BOOLEAN NOT NULL DEFAULT TRUE,
                white_rating_before INTEGER NOT NULL,
                white_rating_after INTEGER NOT NULL,
                black_rating_before INTEGER NOT NULL,
                black_rating_after INTEGER NOT NULL,
                pgn TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                ended_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS friendships (
                id BIGSERIAL PRIMARY KEY,
                user_low_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                user_high_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                requested_by_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                status VARCHAR(12) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CHECK (user_low_id < user_high_id),
                UNIQUE (user_low_id, user_high_id)
            )
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            friendships_requested_by_idx
            ON friendships (requested_by_id, status)
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS direct_messages (
                id BIGSERIAL PRIMARY KEY,
                sender_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                receiver_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                body VARCHAR(500) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                read_at TIMESTAMPTZ,
                CHECK (sender_id <> receiver_id)
            )
        `);

        await pool.query(`
            CREATE INDEX IF NOT EXISTS
            direct_messages_conversation_idx
            ON direct_messages (
                LEAST(sender_id, receiver_id),
                GREATEST(sender_id, receiver_id),
                created_at DESC
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_blocks (
                blocker_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                blocked_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                PRIMARY KEY (blocker_id, blocked_id),
                CHECK (blocker_id <> blocked_id)
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS user_reports (
                id BIGSERIAL PRIMARY KEY,
                reporter_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                reported_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                category VARCHAR(32) NOT NULL,
                details VARCHAR(500) NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                CHECK (reporter_id <> reported_id)
            )
        `);

        console.log("Database initialized");
    } catch (error) {
        console.error(
            "Database initialization failed:",
            error
        );
        throw error;
    }
}

// General Helpers

function getCountryCode(req) {
    if (process.env.NODE_ENV !== "production") {
        return "CA";
    }

    const candidates = [
        req.headers["cf-ipcountry"],
        req.headers["x-vercel-ip-country"],
        req.headers["x-country-code"],
        req.headers["fly-client-country"]
    ];

    for (const candidate of candidates) {
        if (
            typeof candidate === "string" &&
            /^[A-Z]{2}$/.test(candidate)
        ) {
            return candidate;
        }
    }

    return null;
}

function getUserPresence(userId) {
    if (!userId) {
        return "offline";
    }

    for (const game of games.values()) {
        if (game.gameOver) {
            continue;
        }

        if (
            String(game.whiteUserId || "") === String(userId) ||
            String(game.blackUserId || "") === String(userId)
        ) {
            return "in_game";
        }
    }

    const room =
        io.sockets.adapter.rooms.get(
            `user:${userId}`
        );

    return room && room.size > 0
        ? "online"
        : "offline";
}

function publicUser(user) {
    if (!user) {
        return null;
    }

    return {
        username: user.username,
        rating: Number(user.rating),
        wins: Number(user.wins || 0),
        losses: Number(user.losses || 0),
        draws: Number(user.draws || 0),
        country_code:
            user.country_code || null,
        avatar_key:
            user.avatar_key || "knight",
        profile_bio:
            user.profile_bio || "",
        presence: getUserPresence(user.id)
    };
}

function accountUser(user) {
    const safeUser = publicUser(user);

    if (!safeUser) {
        return null;
    }

    return {
        ...safeUser,
        username_changed_at:
            user.username_changed_at || null,
        created_at:
            user.created_at || null
    };
}

function normalizeModeratedText(value) {
    return String(value || "")
        .normalize("NFKD")
        .replace(/\p{M}/gu, "")
        .toLowerCase()
        .replace(/[Ð°Î±É‘]/g, "a")
        .replace(/[ÐµÎµ]/g, "e")
        .replace(/[Ñ–Î¹]/g, "i")
        .replace(/[Ð¾Î¿]/g, "o")
        .replace(/[ÑÏ²]/g, "c")
        .replace(/[Ñ…Ï‡]/g, "x")
        .replace(/[Ñ•]/g, "s")
        .replace(/[Ñ˜]/g, "j")
        .replace(/ph/g, "f")
        .replace(/[0]/g, "o")
        .replace(/[1!|]/g, "i")
        .replace(/[2]/g, "z")
        .replace(/[3]/g, "e")
        .replace(/[4@]/g, "a")
        .replace(/[5$]/g, "s")
        .replace(/[6]/g, "g")
        .replace(/[7+]/g, "t")
        .replace(/[8]/g, "b")
        .replace(/[9]/g, "g")
        .replace(/[^a-z0-9]/g, "")
        .replace(/(.)\1+/g, "$1");
}

const BLOCKED_FRAGMENTS = [
    "fuck",
    "fuk",
    "fuc",
    "fuq",
    "fck",
    "fxck",
    "shit",
    "shiit",
    "sh1t",
    "betch",
    "biitch",
    "b1tch",
    "bitch",
    "cunt",
    "dick",
    "pussy",
    "whore",
    "slut",
    "sex",
    "segs",
    "segg",
    "secks",
    "seks",
    "nigger",
    "nigga",
    "nigg",
    "nigja",
    "nijja",
    "nijj",
    "nija",
    "niga",
    "faggot",
    "fagot",
    "fag",
    "retard",
    "kike",
    "chink"
];

function containsBlockedContent(value) {
    const normalized =
        normalizeModeratedText(value);

    if (!normalized) {
        return false;
    }

    return BLOCKED_FRAGMENTS.some(
        function(fragment) {
            return normalized.includes(fragment);
        }
    );
}

function usernameContainsBlockedWord(username) {
    return containsBlockedContent(username);
}

function validateEmail(email) {
    if (
        typeof email !== "string" ||
        email.length < 3 ||
        email.length > 254
    ) {
        return "Enter a valid email address.";
    }

    if (/[\u0000-\u001f\u007f]/.test(email)) {
        return "Enter a valid email address.";
    }

    const emailPattern =
        /^[^\s@]{1,64}@[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\.[a-z]{2,63}$/i;

    if (!emailPattern.test(email)) {
        return "Enter a valid email address.";
    }

    return null;
}

function validatePassword(password) {
    if (typeof password !== "string") {
        return "Password is required.";
    }

    if (password.length < 8) {
        return "Password must be at least 8 characters.";
    }

    if (password.length > 128) {
        return "Password must be 128 characters or fewer.";
    }

    return null;
}

function validateUsername(username) {
    if (
        typeof username !== "string" ||
        username.length < 3 ||
        username.length > 20
    ) {
        return "Username must be between 3 and 20 characters.";
    }

    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
        return "Username can only contain letters, numbers, and underscores.";
    }

    if (usernameContainsBlockedWord(username)) {
        return "That username is not allowed.";
    }

    return null;
}

function sanitizeGeneratedUsername(value) {
    let username = String(value || "Player")
        .replace(/[^a-zA-Z0-9_]/g, "")
        .slice(0, 16);

    if (username.length < 3) {
        username = "Player";
    }

    if (usernameContainsBlockedWord(username)) {
        username = "Player";
    }

    return username;
}

async function getUniqueGeneratedUsername(baseValue) {
    const base =
        sanitizeGeneratedUsername(baseValue);

    for (let attempt = 0; attempt < 50; attempt++) {
        const suffix =
            attempt === 0
                ? ""
                : String(
                    Math.floor(
                        1000 + Math.random() * 9000
                    )
                );

        const candidate =
            (base.slice(0, 20 - suffix.length) + suffix)
                .slice(0, 20);

        const existing = await pool.query(
            `
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER($1)
                LIMIT 1
            `,
            [candidate]
        );

        if (existing.rows.length === 0) {
            return candidate;
        }
    }

    return `Player${Date.now()}`.slice(0, 20);
}

async function saveSession(req) {
    await new Promise(function(resolve, reject) {
        req.session.save(function(error) {
            if (error) {
                reject(error);
                return;
            }

            resolve();
        });
    });
}

async function regenerateSession(req) {
    await new Promise(function(resolve, reject) {
        req.session.regenerate(function(error) {
            if (error) {
                reject(error);
                return;
            }

            resolve();
        });
    });
}

async function establishSession(req, userId) {
    await regenerateSession(req);
    req.session.userId = userId;
    await saveSession(req);
}

async function getUserById(userId, client = pool) {
    const result = await client.query(
        `
            SELECT
                id,
                username,
                email,
                rating,
                wins,
                losses,
                draws,
                country_code,
                avatar_key,
                profile_bio,
                username_changed_at,
                google_id,
                created_at
            FROM users
            WHERE id = $1
        `,
        [userId]
    );

    return result.rows[0] || null;
}

async function getUserByUsername(username, client = pool) {
    const result = await client.query(
        `
            SELECT
                id,
                username,
                email,
                rating,
                wins,
                losses,
                draws,
                country_code,
                avatar_key,
                profile_bio,
                username_changed_at,
                google_id,
                created_at
            FROM users
            WHERE LOWER(username) = LOWER($1)
            LIMIT 1
        `,
        [username]
    );

    return result.rows[0] || null;
}

async function getFriendship(userAId, userBId, client = pool) {
    const result = await client.query(
        `
            SELECT
                id,
                user_low_id,
                user_high_id,
                requested_by_id,
                status,
                created_at,
                updated_at
            FROM friendships
            WHERE
                user_low_id = LEAST($1::bigint, $2::bigint)
                AND user_high_id = GREATEST($1::bigint, $2::bigint)
            LIMIT 1
        `,
        [userAId, userBId]
    );

    return result.rows[0] || null;
}

function friendshipState(friendship, viewerId, targetId) {
    if (String(viewerId) === String(targetId)) {
        return "self";
    }

    if (!friendship) {
        return "none";
    }

    if (friendship.status === "accepted") {
        return "friends";
    }

    return String(friendship.requested_by_id) === String(viewerId)
        ? "outgoing"
        : "incoming";
}

async function isBlockedBetween(userA, userB) {
    if (!userA || !userB) {
        return false;
    }

    const result = await pool.query(
        `
            SELECT 1
            FROM user_blocks
            WHERE
                (blocker_id = $1 AND blocked_id = $2)
                OR
                (blocker_id = $2 AND blocked_id = $1)
            LIMIT 1
        `,
        [userA, userB]
    );

    return result.rows.length > 0;
}

async function viewerBlockState(viewerId, targetId) {
    const result = await pool.query(
        `
            SELECT blocker_id, blocked_id
            FROM user_blocks
            WHERE
                (blocker_id = $1 AND blocked_id = $2)
                OR
                (blocker_id = $2 AND blocked_id = $1)
            LIMIT 1
        `,
        [viewerId, targetId]
    );

    if (result.rows.length === 0) {
        return "none";
    }

    return String(result.rows[0].blocker_id) === String(viewerId)
        ? "blocked"
        : "blocked_by_them";
}

function cleanDirectMessage(value) {
    if (typeof value !== "string") {
        return "";
    }

    return value
        .replace(/[\u0000-\u001f\u007f]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 500);
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "You must be logged in."
        });
    }

    next();
}

async function sendVerificationEmail(email, code) {
    if (!process.env.BREVO_API_KEY) {
        throw new Error("BREVO_API_KEY is not configured.");
    }
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: { "accept": "application/json", "api-key": process.env.BREVO_API_KEY, "content-type": "application/json" },
        body: JSON.stringify({
            sender: { email: "noreply.pulsechess@gmail.com", name: "Pulse Chess" },
            to: [{ email }],
            subject: "Your Pulse Chess verification code",
            htmlContent: `<div style="font-family:Arial,sans-serif"><h2>Verify your Pulse Chess account</h2><p>Your six-digit code is:</p><div style="font-size:32px;font-weight:700;letter-spacing:8px">${code}</div><p>This code expires in 10 minutes.</p></div>`
        })
    });
    if (!response.ok) throw new Error("Brevo could not send the verification email.");
}

// Authentication

app.post("/api/auth/signup", signupLimiter, async function(req, res) {
    try {
        const username =
            req.body.username?.trim();

        const email =
            req.body.email
                ?.trim()
                .toLowerCase();

        const password = req.body.password;
        const countryCode = getCountryCode(req);

        if (!username || !email || !password) {
            return res.status(400).json({
                error: "Missing required fields."
            });
        }

        const usernameError =
            validateUsername(username);

        if (usernameError) {
            return res.status(400).json({
                error: usernameError
            });
        }

        const emailError =
            validateEmail(email);

        if (emailError) {
            return res.status(400).json({
                error: emailError
            });
        }

        const passwordError =
            validatePassword(password);

        if (passwordError) {
            return res.status(400).json({
                error: passwordError
            });
        }

        const existingUser = await pool.query(
            `
                SELECT id
                FROM users
                WHERE LOWER(username) = LOWER($1)
                   OR LOWER(email) = LOWER($2)
                LIMIT 1
            `,
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({
                error: "Username or email is already in use."
            });
        }

        const passwordHash =
            await argon2.hash(password);

        const code = String(randomInt(100000, 1000000));
        await pool.query(`
            INSERT INTO email_verifications (email, username, password_hash, country_code, code_hash, expires_at)
            VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '10 minutes')
            ON CONFLICT (email) DO UPDATE SET username = EXCLUDED.username, password_hash = EXCLUDED.password_hash,
                country_code = EXCLUDED.country_code, code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at
        `, [email, username, passwordHash, countryCode, await argon2.hash(code)]);
        await sendVerificationEmail(email, code);
        return res.status(202).json({ verificationRequired: true, email });
    } catch (error) {
        console.error("Signup failed:", error);

        if (error?.code === "23505") {
            return res.status(409).json({
                error: "Username or email is already in use."
            });
        }

        return res.status(500).json({
            error: "Failed to create account."
        });
    }
});

app.post("/api/auth/verify-email", signupLimiter, async function(req, res) {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const code = String(req.body.code || "").trim();
        if (validateEmail(email) || !/^\d{6}$/.test(code)) return res.status(400).json({ error: "Enter the six-digit code from your email." });
        const pending = await pool.query("SELECT * FROM email_verifications WHERE email = $1 AND expires_at > NOW()", [email]);
        if (!pending.rows[0] || !(await argon2.verify(pending.rows[0].code_hash, code))) return res.status(400).json({ error: "That code is invalid or expired." });
        const p = pending.rows[0];
        const created = await pool.query(`INSERT INTO users (username, email, password_hash, country_code) VALUES ($1,$2,$3,$4)
            RETURNING id, username, email, rating, wins, losses, draws, country_code, avatar_key, profile_bio, username_changed_at, created_at`, [p.username, p.email, p.password_hash, p.country_code]);
        await pool.query("DELETE FROM email_verifications WHERE email = $1", [email]);
        await establishSession(req, created.rows[0].id);
        return res.status(201).json({ user: accountUser(created.rows[0]) });
    } catch (error) {
        if (error?.code === "23505") return res.status(409).json({ error: "Username or email is already in use." });
        console.error("Email verification failed:", error);
        return res.status(500).json({ error: "Could not verify your email." });
    }
});

app.post("/api/auth/login", loginLimiter, async function(req, res) {
    try {
        const email =
            req.body.email
                ?.trim()
                .toLowerCase();

        const password = req.body.password;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required."
            });
        }

        const emailError =
            validateEmail(email);

        if (emailError) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        if (
            typeof password !== "string" ||
            password.length > 128
        ) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const result = await pool.query(
            `
                SELECT
                    id,
                    username,
                    email,
                    password_hash,
                    rating,
                    wins,
                    losses,
                    draws,
                    country_code,
                    avatar_key,
                    profile_bio,
                    username_changed_at,
                    created_at
                FROM users
                WHERE LOWER(email) = LOWER($1)
                LIMIT 1
            `,
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const user = result.rows[0];

        if (!user.password_hash) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const passwordMatches =
            await argon2.verify(
                user.password_hash,
                password
            );

        if (!passwordMatches) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        await establishSession(
            req,
            user.id
        );

        return res.json({
            user: accountUser(user)
        });
    } catch (error) {
        console.error("Login failed:", error);

        return res.status(500).json({
            error: "Failed to log in."
        });
    }
});

app.post("/api/auth/google", loginLimiter, async function(req, res) {
    try {
        const credential = req.body.credential;

        if (
            typeof credential !== "string" ||
            credential.length < 20
        ) {
            return res.status(400).json({
                error: "Missing Google credential."
            });
        }

        const ticket =
            await googleClient.verifyIdToken({
                idToken: credential,
                audience: GOOGLE_CLIENT_ID
            });

        const payload = ticket.getPayload();

        if (
            !payload ||
            !payload.sub ||
            !payload.email ||
            payload.email_verified !== true
        ) {
            return res.status(401).json({
                error: "Google account could not be verified."
            });
        }

        const googleId = payload.sub;
        const email = payload.email.toLowerCase();
        const countryCode = getCountryCode(req);

        let result = await pool.query(
            `
                SELECT *
                FROM users
                WHERE google_id = $1
                LIMIT 1
            `,
            [googleId]
        );

        let user = result.rows[0] || null;

        if (!user) {
            result = await pool.query(
                `
                    SELECT *
                    FROM users
                    WHERE LOWER(email) = LOWER($1)
                    LIMIT 1
                `,
                [email]
            );

            user = result.rows[0] || null;

            if (user) {
                if (
                    user.google_id &&
                    user.google_id !== googleId
                ) {
                    return res.status(409).json({
                        error: "That email is already linked to another Google account."
                    });
                }

                const linked = await pool.query(
                    `
                        UPDATE users
                        SET
                            google_id = $1,
                            country_code = COALESCE(country_code, $2)
                        WHERE id = $3
                        RETURNING *
                    `,
                    [googleId, countryCode, user.id]
                );

                user = linked.rows[0];
            } else {
                const baseUsername =
                    payload.given_name ||
                    email.split("@")[0] ||
                    "Player";

                const username =
                    await getUniqueGeneratedUsername(
                        baseUsername
                    );

                const created = await pool.query(
                    `
                        INSERT INTO users (
                            username,
                            email,
                            password_hash,
                            google_id,
                            country_code
                        )
                        VALUES ($1, $2, NULL, $3, $4)
                        RETURNING *
                    `,
                    [
                        username,
                        email,
                        googleId,
                        countryCode
                    ]
                );

                user = created.rows[0];
            }
        }

        await establishSession(
            req,
            user.id
        );

        return res.json({
            user: accountUser(user)
        });
    } catch (error) {
        console.error("Google login failed:", error);

        return res.status(401).json({
            error: "Google sign-in failed. Please try again."
        });
    }
});


app.post("/api/auth/logout", function(req, res) {
    req.session.destroy(function(error) {
        if (error) {
            return res.status(500).json({
                error: "Failed to log out."
            });
        }

        res.clearCookie("pulse.sid");

        return res.json({
            success: true
        });
    });
});

// Account

app.put(
    "/api/account/username",
    requireAuth,
    accountLimiter,
    async function(req, res) {
        try {
            const username =
                req.body.username?.trim();

            const usernameError =
                validateUsername(username);

            if (usernameError) {
                return res.status(400).json({
                    error: usernameError
                });
            }

            const currentUser =
                await getUserById(
                    req.session.userId
                );

            if (!currentUser) {
                return res.status(404).json({
                    error: "Account not found."
                });
            }

            if (
                currentUser.username.toLowerCase() ===
                username.toLowerCase()
            ) {
                return res.json({
                    user: accountUser(currentUser)
                });
            }

            if (currentUser.username_changed_at) {
                const changedAt =
                    new Date(
                        currentUser.username_changed_at
                    ).getTime();

                const availableAt =
                    changedAt +
                    USERNAME_CHANGE_COOLDOWN;

                if (Date.now() < availableAt) {
                    return res.status(429).json({
                        error:
                            "You can change your username once every 7 days.",
                        availableAt:
                            new Date(
                                availableAt
                            ).toISOString()
                    });
                }
            }

            const existing = await pool.query(
                `
                    SELECT id
                    FROM users
                    WHERE LOWER(username) = LOWER($1)
                      AND id <> $2
                    LIMIT 1
                `,
                [username, req.session.userId]
            );

            if (existing.rows.length > 0) {
                return res.status(409).json({
                    error: "That username is already taken."
                });
            }

            const result = await pool.query(
                `
                    UPDATE users
                    SET
                        username = $1,
                        username_changed_at = NOW()
                    WHERE id = $2
                    RETURNING *
                `,
                [username, req.session.userId]
            );

            return res.json({
                user: accountUser(result.rows[0])
            });
        } catch (error) {
            console.error(
                "Username update failed:",
                error
            );

            if (error?.code === "23505") {
                return res.status(409).json({
                    error: "That username is already taken."
                });
            }

            return res.status(500).json({
                error: "Could not update username."
            });
        }
    }
);

app.put(
    "/api/account/profile",
    requireAuth,
    accountLimiter,
    async function(req, res) {
        try {
            const avatarKey =
                String(
                    req.body.avatarKey || ""
                ).trim();

            const profileBio =
                String(
                    req.body.bio || ""
                )
                    .replace(
                        /[\u0000-\u001f\u007f]/g,
                        " "
                    )
                    .replace(/\s+/g, " ")
                    .trim()
                    .slice(0, 120);

            if (!AVATAR_KEYS.has(avatarKey)) {
                return res.status(400).json({
                    error: "Choose a valid profile picture."
                });
            }

            if (
                profileBio &&
                containsBlockedContent(profileBio)
            ) {
                return res.status(400).json({
                    error: "Your profile bio contains blocked language."
                });
            }

            const result = await pool.query(
                `
                    UPDATE users
                    SET
                        avatar_key = $1,
                        profile_bio = $2
                    WHERE id = $3
                    RETURNING *
                `,
                [
                    avatarKey,
                    profileBio,
                    req.session.userId
                ]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: "Account not found."
                });
            }

            return res.json({
                user: accountUser(result.rows[0])
            });
        } catch (error) {
            console.error(
                "Profile update failed:",
                error
            );

            return res.status(500).json({
                error: "Could not update profile."
            });
        }
    }
);


// Players & Social

app.get(
    "/api/players/search",
    requireAuth,
    async function(req, res) {
        try {
            const query =
                String(req.query.q || "")
                    .trim()
                    .slice(0, 20);

            if (query.length < 1) {
                return res.json({
                    players: []
                });
            }

            const result = await pool.query(
                `
                    SELECT
                        u.id,
                        u.username,
                        u.rating,
                        u.wins,
                        u.losses,
                        u.draws,
                        u.country_code,
                        u.avatar_key,
                        u.profile_bio,
                        u.created_at,
                        f.status AS friendship_status,
                        f.requested_by_id
                    FROM users u
                    LEFT JOIN friendships f
                        ON f.user_low_id = LEAST(u.id, $2::bigint)
                       AND f.user_high_id = GREATEST(u.id, $2::bigint)
                    WHERE
                        u.id <> $2
                        AND u.username ILIKE $1
                    ORDER BY
                        CASE
                            WHEN LOWER(u.username) = LOWER($3) THEN 0
                            WHEN LOWER(u.username) LIKE LOWER($3 || '%') THEN 1
                            ELSE 2
                        END,
                        u.rating DESC,
                        u.username ASC
                    LIMIT 20
                `,
                [
                    `%${query}%`,
                    req.session.userId,
                    query
                ]
            );

            return res.json({
                players: result.rows.map(function(row) {
                    const friendship =
                        row.friendship_status
                            ? {
                                status:
                                    row.friendship_status,
                                requested_by_id:
                                    row.requested_by_id
                            }
                            : null;

                    return {
                        ...publicUser(row),
                        friendship:
                            friendshipState(
                                friendship,
                                req.session.userId,
                                row.id
                            )
                    };
                })
            });
        } catch (error) {
            console.error(
                "Player search failed:",
                error
            );

            return res.status(500).json({
                error: "Could not search players."
            });
        }
    }
);

app.get(
    "/api/players/:username",
    requireAuth,
    async function(req, res) {
        try {
            const username =
                String(req.params.username || "")
                    .trim()
                    .slice(0, 20);

            const player =
                await getUserByUsername(username);

            if (!player) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            const friendship =
                await getFriendship(
                    req.session.userId,
                    player.id
                );

            const matches =
                await pool.query(
                    `
                        SELECT
                            m.id,
                            m.reason,
                            m.winner_color,
                            m.ended_at,
                            CASE
                                WHEN m.white_user_id = $1 THEN bu.username
                                ELSE wu.username
                            END AS opponent_username,
                            CASE
                                WHEN m.winner_color IS NULL THEN 'draw'
                                WHEN m.white_user_id = $1 AND m.winner_color = 'white' THEN 'win'
                                WHEN m.black_user_id = $1 AND m.winner_color = 'black' THEN 'win'
                                ELSE 'loss'
                            END AS outcome
                        FROM matches m
                        JOIN users wu ON wu.id = m.white_user_id
                        JOIN users bu ON bu.id = m.black_user_id
                        WHERE
                            (m.white_user_id = $1 OR m.black_user_id = $1)
                            AND m.rated = TRUE
                        ORDER BY m.ended_at DESC
                        LIMIT 8
                    `,
                    [player.id]
                );

            const blockState =
                String(player.id) === String(req.session.userId)
                    ? "none"
                    : await viewerBlockState(
                        req.session.userId,
                        player.id
                    );

            return res.json({
                player: {
                    ...publicUser(player),
                    created_at:
                        player.created_at,
                    friendship:
                        friendshipState(
                            friendship,
                            req.session.userId,
                            player.id
                        ),
                    block_state: blockState
                },
                recentMatches:
                    matches.rows.map(function(row) {
                        return {
                            ...row,
                            id: String(row.id)
                        };
                    })
            });
        } catch (error) {
            console.error(
                "Player profile failed:",
                error
            );

            return res.status(500).json({
                error: "Could not load player profile."
            });
        }
    }
);

app.get(
    "/api/social/friends",
    requireAuth,
    async function(req, res) {
        try {
            const result = await pool.query(
                `
                    SELECT
                        u.id,
                        u.username,
                        u.rating,
                        u.wins,
                        u.losses,
                        u.draws,
                        u.country_code,
                        u.avatar_key,
                        u.profile_bio,
                        u.created_at,
                        (
                            SELECT COUNT(*)::int
                            FROM direct_messages dm
                            WHERE
                                dm.sender_id = u.id
                                AND dm.receiver_id = $1
                                AND dm.read_at IS NULL
                        ) AS unread_count
                    FROM friendships f
                    JOIN users u
                        ON u.id = CASE
                            WHEN f.user_low_id = $1
                                THEN f.user_high_id
                            ELSE f.user_low_id
                        END
                    WHERE
                        f.status = 'accepted'
                        AND (
                            f.user_low_id = $1
                            OR f.user_high_id = $1
                        )
                    ORDER BY u.username ASC
                `,
                [req.session.userId]
            );

            return res.json({
                friends: result.rows.map(function(row) {
                    return {
                        ...publicUser(row),
                        friendship: "friends",
                        unread_count:
                            Number(row.unread_count || 0)
                    };
                })
            });
        } catch (error) {
            console.error(
                "Friend list failed:",
                error
            );

            return res.status(500).json({
                error: "Could not load friends."
            });
        }
    }
);

app.get(
    "/api/social/requests",
    requireAuth,
    async function(req, res) {
        try {
            const result = await pool.query(
                `
                    SELECT
                        u.username,
                        u.rating,
                        u.wins,
                        u.losses,
                        u.draws,
                        u.country_code,
                        u.avatar_key,
                        u.profile_bio
                    FROM friendships f
                    JOIN users u
                        ON u.id = f.requested_by_id
                    WHERE
                        f.status = 'pending'
                        AND f.requested_by_id <> $1
                        AND (
                            f.user_low_id = $1
                            OR f.user_high_id = $1
                        )
                    ORDER BY f.created_at DESC
                    LIMIT 50
                `,
                [req.session.userId]
            );

            return res.json({
                requests: result.rows.map(
                    function(row) {
                        return {
                            ...publicUser(row),
                            friendship: "incoming"
                        };
                    }
                )
            });
        } catch (error) {
            console.error(
                "Friend requests failed:",
                error
            );

            return res.status(500).json({
                error: "Could not load friend requests."
            });
        }
    }
);

app.post(
    "/api/social/friends/request",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const username =
                String(req.body.username || "")
                    .trim()
                    .slice(0, 20);

            const target =
                await getUserByUsername(username);

            if (!target) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            if (
                String(target.id) ===
                String(req.session.userId)
            ) {
                return res.status(400).json({
                    error: "You cannot add yourself."
                });
            }

            if (await isBlockedBetween(req.session.userId, target.id)) {
                return res.status(403).json({
                    error: "Friend requests are unavailable for this player."
                });
            }

            const existing =
                await getFriendship(
                    req.session.userId,
                    target.id
                );

            if (
                existing?.status ===
                "accepted"
            ) {
                return res.json({
                    friendship: "friends"
                });
            }

            if (
                existing?.status ===
                "pending"
            ) {
                if (
                    String(
                        existing.requested_by_id
                    ) ===
                    String(req.session.userId)
                ) {
                    return res.json({
                        friendship: "outgoing"
                    });
                }

                await pool.query(
                    `
                        UPDATE friendships
                        SET
                            status = 'accepted',
                            updated_at = NOW()
                        WHERE id = $1
                    `,
                    [existing.id]
                );

                io
                    .to(`user:${target.id}`)
                    .to(
                        `user:${req.session.userId}`
                    )
                    .emit("social-refresh");

                return res.json({
                    friendship: "friends"
                });
            }

            await pool.query(
                `
                    INSERT INTO friendships (
                        user_low_id,
                        user_high_id,
                        requested_by_id,
                        status
                    )
                    VALUES (
                        LEAST($1::bigint, $2::bigint),
                        GREATEST($1::bigint, $2::bigint),
                        $1,
                        'pending'
                    )
                `,
                [
                    req.session.userId,
                    target.id
                ]
            );

            io
                .to(`user:${target.id}`)
                .emit("social-refresh");

            return res.status(201).json({
                friendship: "outgoing"
            });
        } catch (error) {
            console.error(
                "Friend request failed:",
                error
            );

            if (error?.code === "23505") {
                return res.status(409).json({
                    error: "A friend request already exists."
                });
            }

            return res.status(500).json({
                error: "Could not send friend request."
            });
        }
    }
);

app.post(
    "/api/social/friends/respond",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const username =
                String(req.body.username || "")
                    .trim()
                    .slice(0, 20);

            const action =
                String(req.body.action || "")
                    .toLowerCase();

            if (
                action !== "accept" &&
                action !== "decline"
            ) {
                return res.status(400).json({
                    error: "Choose accept or decline."
                });
            }

            const target =
                await getUserByUsername(username);

            if (!target) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            const friendship =
                await getFriendship(
                    req.session.userId,
                    target.id
                );

            if (
                !friendship ||
                friendship.status !== "pending" ||
                String(
                    friendship.requested_by_id
                ) ===
                String(req.session.userId)
            ) {
                return res.status(404).json({
                    error: "Friend request not found."
                });
            }

            if (action === "accept") {
                await pool.query(
                    `
                        UPDATE friendships
                        SET
                            status = 'accepted',
                            updated_at = NOW()
                        WHERE id = $1
                    `,
                    [friendship.id]
                );
            } else {
                await pool.query(
                    `
                        DELETE FROM friendships
                        WHERE id = $1
                    `,
                    [friendship.id]
                );
            }

            io
                .to(`user:${target.id}`)
                .to(
                    `user:${req.session.userId}`
                )
                .emit("social-refresh");

            return res.json({
                friendship:
                    action === "accept"
                        ? "friends"
                        : "none"
            });
        } catch (error) {
            console.error(
                "Friend response failed:",
                error
            );

            return res.status(500).json({
                error: "Could not update friend request."
            });
        }
    }
);

app.delete(
    "/api/social/friends/:username",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const target =
                await getUserByUsername(
                    String(
                        req.params.username || ""
                    ).slice(0, 20)
                );

            if (!target) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            await pool.query(
                `
                    DELETE FROM friendships
                    WHERE
                        user_low_id = LEAST($1::bigint, $2::bigint)
                        AND user_high_id = GREATEST($1::bigint, $2::bigint)
                `,
                [
                    req.session.userId,
                    target.id
                ]
            );

            io
                .to(`user:${target.id}`)
                .to(
                    `user:${req.session.userId}`
                )
                .emit("social-refresh");

            return res.json({
                friendship: "none"
            });
        } catch (error) {
            console.error(
                "Remove friend failed:",
                error
            );

            return res.status(500).json({
                error: "Could not remove friend."
            });
        }
    }
);

app.get(
    "/api/social/messages/:username",
    requireAuth,
    async function(req, res) {
        try {
            const target =
                await getUserByUsername(
                    String(
                        req.params.username || ""
                    ).slice(0, 20)
                );

            if (!target) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            const friendship =
                await getFriendship(
                    req.session.userId,
                    target.id
                );

            if (await isBlockedBetween(req.session.userId, target.id)) {
                return res.status(403).json({
                    error: "Messages are unavailable for this player."
                });
            }

            if (
                !friendship ||
                friendship.status !== "accepted"
            ) {
                return res.status(403).json({
                    error: "You can only message friends."
                });
            }

            const result = await pool.query(
                `
                    SELECT *
                    FROM (
                        SELECT
                            dm.id,
                            dm.sender_id,
                            dm.body,
                            dm.created_at,
                            su.username AS sender_username
                        FROM direct_messages dm
                        JOIN users su
                            ON su.id = dm.sender_id
                        WHERE
                            (
                                dm.sender_id = $1
                                AND dm.receiver_id = $2
                            )
                            OR
                            (
                                dm.sender_id = $2
                                AND dm.receiver_id = $1
                            )
                        ORDER BY dm.created_at DESC
                        LIMIT 100
                    ) recent
                    ORDER BY recent.created_at ASC
                `,
                [
                    req.session.userId,
                    target.id
                ]
            );

            await pool.query(
                `
                    UPDATE direct_messages
                    SET read_at = NOW()
                    WHERE
                        sender_id = $2
                        AND receiver_id = $1
                        AND read_at IS NULL
                `,
                [
                    req.session.userId,
                    target.id
                ]
            );

            return res.json({
                friend: publicUser(target),
                messages: result.rows.map(
                    function(row) {
                        return {
                            id: String(row.id),
                            sender:
                                row.sender_username,
                            mine:
                                String(
                                    row.sender_id
                                ) ===
                                String(
                                    req.session.userId
                                ),
                            body: row.body,
                            created_at:
                                row.created_at
                        };
                    }
                )
            });
        } catch (error) {
            console.error(
                "Load messages failed:",
                error
            );

            return res.status(500).json({
                error: "Could not load messages."
            });
        }
    }
);

app.post(
    "/api/social/messages/:username",
    requireAuth,
    socialMessageLimiter,
    async function(req, res) {
        try {
            const target =
                await getUserByUsername(
                    String(
                        req.params.username || ""
                    ).slice(0, 20)
                );

            if (!target) {
                return res.status(404).json({
                    error: "Player not found."
                });
            }

            const friendship =
                await getFriendship(
                    req.session.userId,
                    target.id
                );

            if (await isBlockedBetween(req.session.userId, target.id)) {
                return res.status(403).json({
                    error: "Messages are unavailable for this player."
                });
            }

            if (
                !friendship ||
                friendship.status !== "accepted"
            ) {
                return res.status(403).json({
                    error: "You can only message friends."
                });
            }

            const message =
                cleanDirectMessage(
                    req.body.message
                );

            if (!message) {
                return res.status(400).json({
                    error: "Type a message first."
                });
            }

            if (
                containsBlockedContent(message)
            ) {
                return res.status(400).json({
                    error: "That message contains blocked language."
                });
            }

            const sender =
                await getUserById(
                    req.session.userId
                );

            const result = await pool.query(
                `
                    INSERT INTO direct_messages (
                        sender_id,
                        receiver_id,
                        body
                    )
                    VALUES ($1, $2, $3)
                    RETURNING id, created_at
                `,
                [
                    req.session.userId,
                    target.id,
                    message
                ]
            );

            const payload = {
                id: String(
                    result.rows[0].id
                ),
                sender:
                    sender.username,
                mine: false,
                body: message,
                created_at:
                    result.rows[0].created_at
            };

            io
                .to(`user:${target.id}`)
                .emit("direct-message", {
                    with:
                        sender.username,
                    message: payload
                });

            return res.status(201).json({
                message: {
                    ...payload,
                    mine: true
                }
            });
        } catch (error) {
            console.error(
                "Send direct message failed:",
                error
            );

            return res.status(500).json({
                error: "Could not send message."
            });
        }
    }
);


// Safety & account controls

app.post(
    "/api/social/block/:username",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const target = await getUserByUsername(
                String(req.params.username || "").slice(0, 20)
            );

            if (!target) {
                return res.status(404).json({ error: "Player not found." });
            }

            if (String(target.id) === String(req.session.userId)) {
                return res.status(400).json({ error: "You cannot block yourself." });
            }

            await pool.query(
                `
                    INSERT INTO user_blocks (blocker_id, blocked_id)
                    VALUES ($1, $2)
                    ON CONFLICT (blocker_id, blocked_id) DO NOTHING
                `,
                [req.session.userId, target.id]
            );

            await pool.query(
                `
                    DELETE FROM friendships
                    WHERE user_low_id = LEAST($1::bigint, $2::bigint)
                      AND user_high_id = GREATEST($1::bigint, $2::bigint)
                `,
                [req.session.userId, target.id]
            );

            io.to(`user:${target.id}`).emit("social-refresh");
            io.to(`user:${req.session.userId}`).emit("social-refresh");

            return res.json({ block_state: "blocked" });
        } catch (error) {
            console.error("Block player failed:", error);
            return res.status(500).json({ error: "Could not block player." });
        }
    }
);

app.delete(
    "/api/social/block/:username",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const target = await getUserByUsername(
                String(req.params.username || "").slice(0, 20)
            );

            if (!target) {
                return res.status(404).json({ error: "Player not found." });
            }

            await pool.query(
                `DELETE FROM user_blocks WHERE blocker_id = $1 AND blocked_id = $2`,
                [req.session.userId, target.id]
            );

            io.to(`user:${target.id}`).emit("social-refresh");
            return res.json({ block_state: "none" });
        } catch (error) {
            console.error("Unblock player failed:", error);
            return res.status(500).json({ error: "Could not unblock player." });
        }
    }
);

app.post(
    "/api/social/report/:username",
    requireAuth,
    socialActionLimiter,
    async function(req, res) {
        try {
            const target = await getUserByUsername(
                String(req.params.username || "").slice(0, 20)
            );

            if (!target) {
                return res.status(404).json({ error: "Player not found." });
            }

            if (String(target.id) === String(req.session.userId)) {
                return res.status(400).json({ error: "You cannot report yourself." });
            }

            const allowed = new Set(["harassment", "spam", "cheating", "username", "other"]);
            const category = allowed.has(String(req.body.category || "").toLowerCase())
                ? String(req.body.category).toLowerCase()
                : "other";
            const details = String(req.body.details || "")
                .replace(/[\u0000-\u001f\u007f]/g, " ")
                .replace(/\s+/g, " ")
                .trim()
                .slice(0, 500);

            await pool.query(
                `
                    INSERT INTO user_reports (reporter_id, reported_id, category, details)
                    VALUES ($1, $2, $3, $4)
                `,
                [req.session.userId, target.id, category, details]
            );

            return res.status(201).json({ success: true });
        } catch (error) {
            console.error("Report player failed:", error);
            return res.status(500).json({ error: "Could not submit report." });
        }
    }
);

app.post(
    "/api/account/signout-all",
    requireAuth,
    accountLimiter,
    async function(req, res) {
        try {
            await pool.query(
                `DELETE FROM session WHERE sess::jsonb ->> 'userId' = $1`,
                [String(req.session.userId)]
            );
        } catch (error) {
            console.warn("Could not revoke every stored session:", error.message);
        }

        req.session.destroy(function() {});
        res.clearCookie("pulse.sid");
        return res.json({ success: true });
    }
);

app.delete(
    "/api/account",
    requireAuth,
    accountLimiter,
    async function(req, res) {
        try {
            const userId = req.session.userId;
            await pool.query("DELETE FROM users WHERE id = $1", [userId]);
            req.session.destroy(function() {});
            res.clearCookie("pulse.sid");
            return res.json({ success: true });
        } catch (error) {
            console.error("Delete account failed:", error);
            return res.status(500).json({ error: "Could not delete account." });
        }
    }
);

app.get("/api/auth/me", async function(req, res) {
    try {
        if (!req.session.userId) {
            return res.json({ user: null });
        }

        const user =
            await getUserById(
                req.session.userId
            );

        if (!user) {
            req.session.destroy(function() {});
            return res.json({ user: null });
        }

        return res.json({
            user: accountUser(user)
        });
    } catch (error) {
        console.error(
            "Session check failed:",
            error
        );

        return res.status(500).json({
            error: "Failed to check session."
        });
    }
});

app.get(
    "/api/matches/:id",
    requireAuth,
    async function(req, res, next) {
        if (req.params.id === "me") {
            return next();
        }

        try {
            const matchId = String(req.params.id || "");
            if (!/^\d+$/.test(matchId)) {
                return res.status(400).json({ error: "Invalid match." });
            }

            const result = await pool.query(
                `
                    SELECT
                        m.*,
                        wu.username AS white_username,
                        wu.rating AS white_rating,
                        wu.avatar_key AS white_avatar_key,
                        wu.country_code AS white_country_code,
                        bu.username AS black_username,
                        bu.rating AS black_rating,
                        bu.avatar_key AS black_avatar_key,
                        bu.country_code AS black_country_code
                    FROM matches m
                    JOIN users wu ON wu.id = m.white_user_id
                    JOIN users bu ON bu.id = m.black_user_id
                    WHERE m.id = $1
                    LIMIT 1
                `,
                [matchId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({ error: "Match not found." });
            }

            const row = result.rows[0];

            let finalFen = null;
            if (row.pgn) {
                try {
                    const replay = new Chess();
                    replay.loadPgn(row.pgn);
                    finalFen = replay.fen();
                } catch (error) {
                    finalFen = null;
                }
            }

            return res.json({
                match: {
                    id: String(row.id),
                    reason: row.reason,
                    winner_color: row.winner_color,
                    rated: row.rated,
                    pgn: row.pgn || "",
                    final_fen: finalFen,
                    created_at: row.created_at,
                    ended_at: row.ended_at,
                    white: {
                        username: row.white_username,
                        rating: Number(row.white_rating),
                        rating_before: Number(row.white_rating_before),
                        rating_after: Number(row.white_rating_after),
                        avatar_key: row.white_avatar_key,
                        country_code: row.white_country_code
                    },
                    black: {
                        username: row.black_username,
                        rating: Number(row.black_rating),
                        rating_before: Number(row.black_rating_before),
                        rating_after: Number(row.black_rating_after),
                        avatar_key: row.black_avatar_key,
                        country_code: row.black_country_code
                    }
                }
            });
        } catch (error) {
            console.error("Match detail failed:", error);
            return res.status(500).json({ error: "Could not load match." });
        }
    }
);

// Leaderboards

app.get("/api/leaderboard", async function(req, res) {
    try {
        const requestedLimit =
            Number(req.query.limit || 25);

        const limit =
            [10, 25, 50].includes(requestedLimit)
                ? requestedLimit
                : 25;

        const scope =
            req.query.scope === "country"
                ? "country"
                : "global";

        let country =
            typeof req.query.country === "string"
                ? req.query.country.toUpperCase()
                : null;

        if (
            scope === "country" &&
            (!country || !/^[A-Z]{2}$/.test(country))
        ) {
            if (req.session.userId) {
                const current =
                    await getUserById(
                        req.session.userId
                    );

                country =
                    current?.country_code || null;
            }
        }

        let result;

        if (scope === "country" && country) {
            result = await pool.query(
                `
                    SELECT
                        id,
                        username,
                        rating,
                        wins,
                        losses,
                        draws,
                        country_code,
                        avatar_key,
                        profile_bio,
                        created_at,
                        RANK() OVER (
                            ORDER BY rating DESC, wins DESC, id ASC
                        ) AS rank
                    FROM users
                    WHERE country_code = $1
                    ORDER BY rating DESC, wins DESC, id ASC
                    LIMIT $2
                `,
                [country, limit]
            );
        } else {
            result = await pool.query(
                `
                    SELECT
                        id,
                        username,
                        rating,
                        wins,
                        losses,
                        draws,
                        country_code,
                        avatar_key,
                        profile_bio,
                        created_at,
                        RANK() OVER (
                            ORDER BY rating DESC, wins DESC, id ASC
                        ) AS rank
                    FROM users
                    ORDER BY rating DESC, wins DESC, id ASC
                    LIMIT $1
                `,
                [limit]
            );
        }

        const countResult =
            await pool.query(
                "SELECT COUNT(*)::int AS count FROM users"
            );

        return res.json({
            scope,
            country,
            totalPlayers:
                countResult.rows[0].count,
            players: result.rows.map(function(row) {
                return {
                    ...publicUser(row),
                    rank: Number(row.rank)
                };
            })
        });
    } catch (error) {
        console.error(
            "Leaderboard failed:",
            error
        );

        return res.status(500).json({
            error: "Could not load leaderboard."
        });
    }
});

app.get(
    "/api/matches/me",
    requireAuth,
    async function(req, res) {
        try {
            const result = await pool.query(
                `
                    SELECT
                        m.id,
                        m.reason,
                        m.winner_color,
                        m.created_at,
                        CASE
                            WHEN m.white_user_id = $1 THEN bu.username
                            ELSE wu.username
                        END AS opponent_username,
                        CASE
                            WHEN m.white_user_id = $1 THEN bu.country_code
                            ELSE wu.country_code
                        END AS opponent_country_code,
                        CASE
                            WHEN m.white_user_id = $1 THEN bu.avatar_key
                            ELSE wu.avatar_key
                        END AS opponent_avatar_key,
                        CASE
                            WHEN m.white_user_id = $1 THEN m.white_rating_after - m.white_rating_before
                            ELSE m.black_rating_after - m.black_rating_before
                        END AS rating_delta,
                        CASE
                            WHEN m.winner_color IS NULL THEN 'draw'
                            WHEN m.white_user_id = $1 AND m.winner_color = 'white' THEN 'win'
                            WHEN m.black_user_id = $1 AND m.winner_color = 'black' THEN 'win'
                            ELSE 'loss'
                        END AS outcome
                    FROM matches m
                    JOIN users wu ON wu.id = m.white_user_id
                    JOIN users bu ON bu.id = m.black_user_id
                    WHERE
                        (m.white_user_id = $1 OR m.black_user_id = $1)
                        AND m.rated = TRUE
                    ORDER BY m.created_at DESC
                    LIMIT 10
                `,
                [req.session.userId]
            );

            return res.json({
                matches: result.rows.map(function(row) {
                    return {
                        ...row,
                        id: String(row.id),
                        rating_delta:
                            Number(row.rating_delta)
                    };
                })
            });
        } catch (error) {
            console.error(
                "Recent matches failed:",
                error
            );

            return res.status(500).json({
                error: "Could not load matches."
            });
        }
    }
);


const reviewLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    limit: 6,
    standardHeaders: "draft-8",
    legacyHeaders: false,
    message: { error: "Too many game reviews. Try again in a few minutes." }
});

function classifyMoveLoss(loss, isBestMove) {
    if (isBestMove || loss <= 18) return "Best";
    if (loss <= 45) return "Excellent";
    if (loss <= 90) return "Good";
    if (loss <= 160) return "Inaccuracy";
    if (loss <= 320) return "Mistake";
    return "Blunder";
}

app.post(
    "/api/analysis/review",
    requireAuth,
    reviewLimiter,
    async function(req, res) {
        const pgn = String(req.body.pgn || "").trim().slice(0, 30000);

        if (!pgn) {
            return res.status(400).json({ error: "No game was provided." });
        }

        const loaded = new Chess();
        try {
            loaded.loadPgn(pgn);
        } catch (error) {
            return res.status(400).json({ error: "That PGN could not be read." });
        }

        const history = loaded.history({ verbose: true });
        if (history.length === 0) {
            return res.status(400).json({ error: "The game has no moves to review." });
        }

        const maxPlies = Math.min(history.length, 120);
        const replay = new Chess();
        const positions = [replay.fen()];
        const moves = [];

        for (let i = 0; i < maxPlies; i++) {
            const move = history[i];
            moves.push({
                san: move.san,
                color: move.color === "w" ? "white" : "black",
                uci: `${move.from}${move.to}${move.promotion || ""}`
            });
            replay.move({ from: move.from, to: move.to, promotion: move.promotion || "q" });
            positions.push(replay.fen());
        }

        let engine = null;

        try {
            engine = createStockfishEngine({ engineFlavor: "full" });
            await engine.initialize();

            const evaluations = [];
            const bestMoves = [];

            for (let i = 0; i < positions.length; i++) {
                const positionChess = new Chess(positions[i]);

                if (positionChess.isCheckmate()) {
                    const whiteLost = positionChess.turn() === "w";
                    evaluations.push(whiteLost ? -100000 : 100000);
                    bestMoves.push(null);
                    continue;
                }

                if (positionChess.isDraw()) {
                    evaluations.push(0);
                    bestMoves.push(null);
                    continue;
                }

                const analysis = await engine.analyzePosition(positions[i], 95);
                evaluations.push(Number(analysis.cp || 0));
                bestMoves.push(analysis.bestMove || null);
            }

            const reviewed = moves.map(function(move, index) {
                const before = evaluations[index];
                const after = evaluations[index + 1];
                const rawLoss = move.color === "white"
                    ? before - after
                    : after - before;
                const loss = Math.max(0, Math.min(10000, Math.round(rawLoss)));
                const isBestMove = Boolean(bestMoves[index]) && bestMoves[index] === move.uci;

                return {
                    ply: index + 1,
                    moveNumber: Math.floor(index / 2) + 1,
                    color: move.color,
                    san: move.san,
                    classification: classifyMoveLoss(loss, isBestMove),
                    centipawnLoss: loss,
                    evaluation: Math.round(after) / 100,
                    bestMove: bestMoves[index]
                };
            });

            const counts = {};
            for (const item of reviewed) {
                counts[item.classification] = (counts[item.classification] || 0) + 1;
            }

            return res.json({
                moves: reviewed,
                summary: counts,
                truncated: history.length > maxPlies
            });
        } catch (error) {
            console.error("Game review failed:", error);
            return res.status(500).json({
                error: "Stockfish review could not run. Make sure npm.cmd install completed and restart the server."
            });
        } finally {
            engine?.close();
        }
    }
);

// Express

// Public files

app.use(
    "/assets",
    express.static(
        path.join(__dirname, "assets"),
        { dotfiles: "deny" }
    )
);

app.get("/", function(req, res) {
    res.sendFile(
        path.join(__dirname, "index.html")
    );
});

for (const file of [
    "index.html",
    "style.css",
    "script.js",
    "pieces.js"
]) {
    app.get(`/${file}`, function(req, res) {
        res.sendFile(
            path.join(__dirname, file)
        );
    });
}

function getTimeControl(key) {
    return TIME_CONTROLS[key] || TIME_CONTROLS.rapid10;
}

function normalizeTimeControlKey(value) {
    return Object.prototype.hasOwnProperty.call(TIME_CONTROLS, value)
        ? value
        : "rapid10";
}

// Chess Helpers

function coordinatesToSquare(y, x) {
    const files = "abcdefgh";
    return `${files[x]}${8 - y}`;
}

function squareToCoordinates(square) {
    const files = "abcdefgh";

    return {
        x: files.indexOf(square[0]),
        y: 8 - Number(square[1])
    };
}

function promotionWord(letter) {
    const names = {
        q: "queen",
        r: "rook",
        b: "bishop",
        n: "knight"
    };

    return names[letter] || null;
}

function normalizeNetworkMove(moveResult) {
    const to =
        squareToCoordinates(moveResult.to);

    const move = {
        x: to.x,
        y: to.y
    };

    if (moveResult.flags?.includes("e")) {
        move.enPassant = true;
    }

    if (moveResult.flags?.includes("k")) {
        move.castle = "kingSide";
    }

    if (moveResult.flags?.includes("q")) {
        move.castle = "queenSide";
    }

    if (moveResult.promotion) {
        move.promotion =
            promotionWord(
                moveResult.promotion
            );
    }

    return move;
}

function oppositeColor(color) {
    return color === "white"
        ? "black"
        : "white";
}

function colorToChess(color) {
    return color === "white" ? "w" : "b";
}

function chessToColor(color) {
    return color === "w" ? "white" : "black";
}

function expectedScore(ratingA, ratingB) {
    return 1 /
        (
            1 +
            Math.pow(
                10,
                (ratingB - ratingA) / 400
            )
        );
}

function calculateNewRating(
    rating,
    opponentRating,
    score
) {
    return Math.round(
        rating +
        ELO_K *
        (
            score -
            expectedScore(
                rating,
                opponentRating
            )
        )
    );
}

function getDrawReason(chess) {
    if (
        typeof chess.isInsufficientMaterial === "function" &&
        chess.isInsufficientMaterial()
    ) {
        return "insufficient-material";
    }

    if (
        typeof chess.isThreefoldRepetition === "function" &&
        chess.isThreefoldRepetition()
    ) {
        return "threefold-repetition";
    }

    if (
        typeof chess.isDrawByFiftyMoves === "function" &&
        chess.isDrawByFiftyMoves()
    ) {
        return "fifty-move";
    }

    return "draw";
}

async function socketUser(socket) {
    const userId =
        socket.request.session?.userId;

    if (!userId) {
        return null;
    }

    return getUserById(userId);
}

function clearPlayerRoom(socket) {
    if (!socket) {
        return;
    }

    const roomId = socket.data.roomId;

    socket.data.roomId = null;
    socket.data.color = null;
    socket.data.privateCode = null;

    if (roomId) {
        socket.leave(roomId);
    }
}

function getSocket(socketId) {
    if (!socketId) {
        return null;
    }

    return io.sockets.sockets.get(socketId) || null;
}

async function createHumanGame(
    whiteSocket,
    blackSocket,
    mode = "quick",
    timeControlKey = "rapid10"
) {
    const whiteUser =
        await socketUser(whiteSocket);

    const blackUser =
        await socketUser(blackSocket);

    if (!whiteUser || !blackUser) {
        return null;
    }

    const roomId = randomUUID();
    const normalizedTimeControl = normalizeTimeControlKey(timeControlKey);
    const timeControl = getTimeControl(normalizedTimeControl);

    const game = {
        roomId,
        mode,
        timeControlKey: normalizedTimeControl,
        timeControlLabel: timeControl.label,
        incrementMs: timeControl.incrementMs,
        chess: new Chess(),

        whiteSocketId: whiteSocket.id,
        blackSocketId: blackSocket.id,

        whiteUserId: String(whiteUser.id),
        blackUserId: String(blackUser.id),

        whiteUser: publicUser(whiteUser),
        blackUser: publicUser(blackUser),

        currentTurn: "white",
        whiteTime: timeControl.initialMs,
        blackTime: timeControl.initialMs,
        lastMoveTime: Date.now(),

        timeoutId: null,
        botTimeoutId: null,
        reconnectTimeouts: { white: null, black: null },
        disconnectCounts: { white: 0, black: 0 },
        drawOfferFrom: null,
        gameOver: false,

        rated:
            mode === "quick" &&
            String(whiteUser.id) !==
                String(blackUser.id),

        startedAt: new Date()
    };

    games.set(roomId, game);

    whiteSocket.join(roomId);
    blackSocket.join(roomId);

    whiteSocket.data.roomId = roomId;
    whiteSocket.data.color = "white";

    blackSocket.data.roomId = roomId;
    blackSocket.data.color = "black";

    return game;
}

async function createBotGame(
    socket,
    difficulty = "club1000",
    timeControlKey = "rapid10"
) {
    const user = await socketUser(socket);

    if (!user) {
        return null;
    }

    const selectedDifficulty =
        BOT_CONFIGS[difficulty]
            ? difficulty
            : "club1000";

    const botConfig =
        BOT_CONFIGS[selectedDifficulty];

    const roomId = randomUUID();
    const normalizedTimeControl = normalizeTimeControlKey(timeControlKey);
    const timeControl = getTimeControl(normalizedTimeControl);

    const game = {
        roomId,
        mode: "bot",
        botDifficulty: selectedDifficulty,
        timeControlKey: normalizedTimeControl,
        timeControlLabel: timeControl.label,
        incrementMs: timeControl.incrementMs,
        chess: new Chess(),

        whiteSocketId: socket.id,
        blackSocketId: null,

        whiteUserId: String(user.id),
        blackUserId: null,

        whiteUser: publicUser(user),
        blackUser: {
            username: botConfig.name,
            rating: botConfig.rating,
            wins: 0,
            losses: 0,
            draws: 0,
            country_code: null,
            avatar_key: "bolt",
            profile_bio: "",
            username_changed_at: null,
            created_at: null
        },

        currentTurn: "white",
        whiteTime: timeControl.initialMs,
        blackTime: timeControl.initialMs,
        lastMoveTime: Date.now(),

        timeoutId: null,
        botTimeoutId: null,
        reconnectTimeouts: { white: null, black: null },
        disconnectCounts: { white: 0, black: 0 },
        drawOfferFrom: null,
        botEngine: null,
        botEngineFailed: false,
        gameOver: false,
        rated: false,
        startedAt: new Date()
    };

    games.set(roomId, game);
    socket.join(roomId);

    socket.data.roomId = roomId;
    socket.data.color = "white";

    return game;
}

function matchPayload(game, color) {
    const you =
        color === "white"
            ? game.whiteUser
            : game.blackUser;

    const opponent =
        color === "white"
            ? game.blackUser
            : game.whiteUser;

    return {
        roomId: game.roomId,
        color,
        mode: game.mode,
        botDifficulty:
            game.botDifficulty || null,
        timeControlKey: game.timeControlKey || "rapid10",
        timeControlLabel: game.timeControlLabel || "10+0 Rapid",
        incrementMs: Number(game.incrementMs || 0),
        rated: game.rated,
        you,
        opponent,
        white: game.whiteUser,
        black: game.blackUser,
        fen: game.chess.fen(),
        pgn: game.chess.pgn(),
        currentTurn: game.currentTurn,
        clocks: getRemainingTimes(game)
    };
}

function getRemainingTimes(game) {
    let whiteTime = game.whiteTime;
    let blackTime = game.blackTime;

    if (!game.gameOver) {
        const elapsed =
            Date.now() -
            game.lastMoveTime;

        if (game.currentTurn === "white") {
            whiteTime -= elapsed;
        } else {
            blackTime -= elapsed;
        }
    }

    return {
        whiteTime: Math.max(0, whiteTime),
        blackTime: Math.max(0, blackTime)
    };
}

function updateActiveClock(game) {
    const elapsed =
        Date.now() -
        game.lastMoveTime;

    if (game.currentTurn === "white") {
        game.whiteTime =
            Math.max(
                0,
                game.whiteTime - elapsed
            );
    } else {
        game.blackTime =
            Math.max(
                0,
                game.blackTime - elapsed
            );
    }

    game.lastMoveTime = Date.now();
}

function sendClock(game) {
    const times = getRemainingTimes(game);

    io.to(game.roomId).emit(
        "clock-update",
        {
            whiteTime: times.whiteTime,
            blackTime: times.blackTime,
            currentTurn: game.currentTurn,
            serverTime: Date.now()
        }
    );
}

function stopGameTimers(game) {
    if (game.timeoutId !== null) {
        clearTimeout(game.timeoutId);
        game.timeoutId = null;
    }

    if (game.botTimeoutId !== null) {
        clearTimeout(game.botTimeoutId);
        game.botTimeoutId = null;
    }

    if (game.reconnectTimeouts) {
        for (const color of ["white", "black"]) {
            if (game.reconnectTimeouts[color]) {
                clearTimeout(game.reconnectTimeouts[color]);
                game.reconnectTimeouts[color] = null;
            }
        }
    }
}

function removeGame(roomId) {
    const game = games.get(roomId);

    if (!game) {
        return;
    }

    stopGameTimers(game);

    if (game.botEngine) {
        game.botEngine.close();
        game.botEngine = null;
    }

    clearPlayerRoom(
        getSocket(game.whiteSocketId)
    );

    clearPlayerRoom(
        getSocket(game.blackSocketId)
    );

    games.delete(roomId);
}

async function persistRatedResult(
    game,
    winner,
    reason
) {
    const client = await pool.connect();

    try {
        await client.query("BEGIN");

        const ids = [
            String(game.whiteUserId),
            String(game.blackUserId)
        ].sort(function(a, b) {
            return Number(a) - Number(b);
        });

        const locked = await client.query(
            `
                SELECT *
                FROM users
                WHERE id IN ($1, $2)
                ORDER BY id
                FOR UPDATE
            `,
            ids
        );

        const white = locked.rows.find(
            function(row) {
                return String(row.id) ===
                    String(game.whiteUserId);
            }
        );

        const black = locked.rows.find(
            function(row) {
                return String(row.id) ===
                    String(game.blackUserId);
            }
        );

        if (!white || !black) {
            throw new Error(
                "Could not load both players for rating update."
            );
        }

        let whiteScore = 0.5;
        let blackScore = 0.5;

        if (winner === "white") {
            whiteScore = 1;
            blackScore = 0;
        } else if (winner === "black") {
            whiteScore = 0;
            blackScore = 1;
        }

        const whiteBefore = Number(white.rating);
        const blackBefore = Number(black.rating);

        const whiteAfter =
            calculateNewRating(
                whiteBefore,
                blackBefore,
                whiteScore
            );

        const blackAfter =
            calculateNewRating(
                blackBefore,
                whiteBefore,
                blackScore
            );

        const whiteWin = winner === "white" ? 1 : 0;
        const whiteLoss = winner === "black" ? 1 : 0;
        const blackWin = winner === "black" ? 1 : 0;
        const blackLoss = winner === "white" ? 1 : 0;
        const draw = winner === null ? 1 : 0;

        await client.query(
            `
                UPDATE users
                SET
                    rating = $1,
                    wins = wins + $2,
                    losses = losses + $3,
                    draws = draws + $4
                WHERE id = $5
            `,
            [
                whiteAfter,
                whiteWin,
                whiteLoss,
                draw,
                white.id
            ]
        );

        await client.query(
            `
                UPDATE users
                SET
                    rating = $1,
                    wins = wins + $2,
                    losses = losses + $3,
                    draws = draws + $4
                WHERE id = $5
            `,
            [
                blackAfter,
                blackWin,
                blackLoss,
                draw,
                black.id
            ]
        );

        await client.query(
            `
                INSERT INTO matches (
                    white_user_id,
                    black_user_id,
                    winner_color,
                    reason,
                    rated,
                    white_rating_before,
                    white_rating_after,
                    black_rating_before,
                    black_rating_after,
                    pgn,
                    created_at,
                    ended_at
                )
                VALUES (
                    $1, $2, $3, $4, TRUE,
                    $5, $6, $7, $8, $9, $10, NOW()
                )
            `,
            [
                white.id,
                black.id,
                winner,
                reason,
                whiteBefore,
                whiteAfter,
                blackBefore,
                blackAfter,
                game.chess.pgn(),
                game.startedAt
            ]
        );

        await client.query("COMMIT");

        return {
            white: {
                oldRating: whiteBefore,
                newRating: whiteAfter,
                ratingDelta:
                    whiteAfter - whiteBefore
            },
            black: {
                oldRating: blackBefore,
                newRating: blackAfter,
                ratingDelta:
                    blackAfter - blackBefore
            }
        };
    } catch (error) {
        await client.query("ROLLBACK");
        throw error;
    } finally {
        client.release();
    }
}

async function finalizeGame(
    game,
    { reason, winner }
) {
    if (!game || game.gameOver) {
        return;
    }

    game.gameOver = true;
    stopGameTimers(game);

    let ratings = {
        white: {
            oldRating: game.whiteUser.rating,
            newRating: game.whiteUser.rating,
            ratingDelta: 0
        },
        black: {
            oldRating: game.blackUser.rating,
            newRating: game.blackUser.rating,
            ratingDelta: 0
        }
    };

    if (game.rated) {
        try {
            ratings =
                await persistRatedResult(
                    game,
                    winner,
                    reason
                );
        } catch (error) {
            console.error(
                "Rating update failed:",
                error
            );
        }
    }

    const whiteSocket =
        getSocket(game.whiteSocketId);

    const blackSocket =
        getSocket(game.blackSocketId);

    const shared = {
        reason,
        winner,
        rated: game.rated,
        mode: game.mode,
        fen: game.chess.fen(),
        pgn: game.chess.pgn(),
        timeControlKey: game.timeControlKey || "rapid10",
        timeControlLabel: game.timeControlLabel || "10+0 Rapid"
    };

    if (whiteSocket) {
        whiteSocket.emit("game-ended", {
            ...shared,
            ...ratings.white,
            outcome:
                winner === null
                    ? "draw"
                    : winner === "white"
                        ? "win"
                        : "loss"
        });
    }

    if (blackSocket) {
        blackSocket.emit("game-ended", {
            ...shared,
            ...ratings.black,
            outcome:
                winner === null
                    ? "draw"
                    : winner === "black"
                        ? "win"
                        : "loss"
        });
    }

    io.to(game.roomId).emit("spectator-game-ended", shared);

    removeGame(game.roomId);
}

function scheduleTimeout(game) {
    if (!game || game.gameOver) {
        return;
    }

    if (
        game.mode === "bot" &&
        game.currentTurn === "black"
    ) {
        return;
    }

    if (game.timeoutId !== null) {
        clearTimeout(game.timeoutId);
    }

    const remainingTime =
        game.currentTurn === "white"
            ? game.whiteTime
            : game.blackTime;

    const color = game.currentTurn;

    game.timeoutId = setTimeout(
        async function() {
            if (
                game.gameOver ||
                !games.has(game.roomId) ||
                game.currentTurn !== color
            ) {
                return;
            }

            updateActiveClock(game);

            const timeLeft =
                color === "white"
                    ? game.whiteTime
                    : game.blackTime;

            if (timeLeft > 0) {
                scheduleTimeout(game);
                return;
            }

            sendClock(game);

            await finalizeGame(game, {
                reason: "timeout",
                winner: oppositeColor(color)
            });
        },
        Math.max(1, remainingTime)
    );
}

function fallbackBotMove(chess, difficulty) {
    const legalMoves = chess.moves({ verbose: true });

    if (legalMoves.length === 0) {
        return null;
    }

    const config =
        BOT_CONFIGS[difficulty] ||
        BOT_CONFIGS.club1000;

    if (
        config.randomChance >= 1 ||
        Math.random() < config.randomChance
    ) {
        return legalMoves[
            Math.floor(Math.random() * legalMoves.length)
        ];
    }

    const pieceValues = {
        p: 1,
        n: 3.2,
        b: 3.3,
        r: 5,
        q: 9,
        k: 0
    };

    return [...legalMoves]
        .map(function(move) {
            let score = Math.random() * 0.25;

            if (move.captured) {
                score +=
                    (pieceValues[move.captured] || 1) * 3;
                score -=
                    (pieceValues[move.piece] || 0) * 0.12;
            }

            if (move.san?.includes("+")) {
                score += 2;
            }

            if (move.san?.includes("#")) {
                score += 1000;
            }

            if (move.promotion) {
                score += 9;
            }

            return { move, score };
        })
        .sort(function(a, b) {
            return b.score - a.score;
        })[0].move;
}

function resolveStockfishEnginePath(
    engineFlavor = "lite"
) {
    const packagePath =
        require.resolve("stockfish/package.json");

    const packageDirectory =
        path.dirname(packagePath);

    const candidates =
        engineFlavor === "full"
            ? [
                "stockfish-18-single.js",
                "stockfish-18-lite-single.js",
                "stockfish-18.js",
                "stockfish-18-lite.js"
            ]
            : [
                "stockfish-18-lite-single.js",
                "stockfish-18-single.js",
                "stockfish-18-lite.js",
                "stockfish-18.js"
            ];

    for (const filename of candidates) {
        const candidate =
            path.join(
                packageDirectory,
                "bin",
                filename
            );

        if (fs.existsSync(candidate)) {
            return candidate;
        }
    }

    throw new Error(
        "Stockfish engine files were not found. Run npm.cmd install."
    );
}

function createStockfishEngine(
    config = {}
) {
    const enginePath =
        resolveStockfishEnginePath(
            config.engineFlavor
        );

    console.log(
        "Starting Stockfish:",
        path.basename(enginePath)
    );

    const child = spawn(
        process.execPath,
        [enginePath],
        {
            stdio: ["pipe", "pipe", "pipe"],
            windowsHide: true
        }
    );

    let closed = false;
    let stdoutBuffer = "";
    const waiters = [];
    const lineHandlers = new Set();

    function rejectAll(error) {
        while (waiters.length > 0) {
            const waiter = waiters.shift();
            clearTimeout(waiter.timeoutId);
            waiter.reject(error);
        }
    }

    function handleLine(line) {
        for (const handler of lineHandlers) {
            try {
                handler(line);
            } catch (error) {
                // Ignore a review listener failure.
            }
        }

        for (let index = 0; index < waiters.length; index++) {
            const waiter = waiters[index];

            if (!waiter.test(line)) {
                continue;
            }

            waiters.splice(index, 1);
            clearTimeout(waiter.timeoutId);
            waiter.resolve(line);
            return;
        }
    }

    child.stdout.on("data", function(chunk) {
        stdoutBuffer += chunk.toString();
        const lines = stdoutBuffer.split(/\r?\n/);
        stdoutBuffer = lines.pop() || "";

        for (const line of lines) {
            handleLine(line.trim());
        }
    });

    child.stderr.on("data", function() {
        // Stockfish can write harmless diagnostics to stderr.
    });

    child.on("error", function(error) {
        closed = true;
        rejectAll(error);
    });

    child.on("exit", function(code) {
        if (closed) {
            return;
        }

        closed = true;
        rejectAll(
            new Error(
                `Stockfish exited unexpectedly (${code ?? "unknown"}).`
            )
        );
    });

    function send(command) {
        if (closed || !child.stdin.writable) {
            throw new Error("Stockfish is not available.");
        }

        child.stdin.write(`${command}\n`);
    }

    function waitFor(test, timeoutMs = 5000) {
        return new Promise(function(resolve, reject) {
            const waiter = {
                test,
                resolve,
                reject,
                timeoutId: null
            };

            waiter.timeoutId = setTimeout(
                function() {
                    const index = waiters.indexOf(waiter);

                    if (index >= 0) {
                        waiters.splice(index, 1);
                    }

                    reject(
                        new Error("Stockfish response timed out.")
                    );
                },
                timeoutMs
            );

            waiters.push(waiter);
        });
    }

    async function ready() {
        send("isready");
        await waitFor(
            function(line) {
                return line === "readyok";
            },
            15000
        );
    }

    async function initialize() {
        send("uci");
        await waitFor(
            function(line) {
                return line === "uciok";
            },
            20000
        );

        send(
            "setoption name Hash value 64"
        );
        send(
            "setoption name MultiPV value 1"
        );
        send(
            "setoption name Move Overhead value 30"
        );

        await ready();
    }

    async function bestMove(fen, config) {
        send("stop");

        if (config.eloLimit) {
            send(
                "setoption name UCI_LimitStrength value true"
            );
            send(
                `setoption name UCI_Elo value ${config.eloLimit}`
            );
        } else {
            send(
                "setoption name UCI_LimitStrength value false"
            );
            send(
                `setoption name Skill Level value ${config.skillLevel ?? 0}`
            );
        }

        await ready();

        send(`position fen ${fen}`);
        send(`go movetime ${config.thinkMs}`);

        const line = await waitFor(
            function(output) {
                return output.startsWith("bestmove ");
            },
            Math.max(5000, config.thinkMs + 4000)
        );

        const uciMove =
            line.split(/\s+/)[1] || "";

        if (
            !/^[a-h][1-8][a-h][1-8][qrbn]?$/.test(
                uciMove
            )
        ) {
            return null;
        }

        return {
            from: uciMove.slice(0, 2),
            to: uciMove.slice(2, 4),
            promotion:
                uciMove.length === 5
                    ? uciMove[4]
                    : undefined
        };
    }

    async function analyzePosition(fen, thinkMs = 110) {
        send("stop");
        send("setoption name UCI_LimitStrength value false");
        send("setoption name Skill Level value 20");
        await ready();

        let scoreCp = 0;
        let mate = null;
        let depth = 0;

        const turn = String(fen).split(/\s+/)[1] || "w";

        const listener = function(line) {
            if (!line.startsWith("info ") || !line.includes(" score ")) {
                return;
            }

            const depthMatch = line.match(/\bdepth\s+(\d+)/);
            if (depthMatch) {
                depth = Number(depthMatch[1]);
            }

            const cpMatch = line.match(/\bscore\s+cp\s+(-?\d+)/);
            const mateMatch = line.match(/\bscore\s+mate\s+(-?\d+)/);

            if (cpMatch) {
                scoreCp = Number(cpMatch[1]);
                mate = null;
            } else if (mateMatch) {
                mate = Number(mateMatch[1]);
                scoreCp = mate > 0 ? 100000 : -100000;
            }
        };

        lineHandlers.add(listener);

        try {
            send(`position fen ${fen}`);
            send(`go movetime ${Math.max(60, Number(thinkMs) || 110)}`);

            const line = await waitFor(
                function(output) {
                    return output.startsWith("bestmove ");
                },
                Math.max(5000, Number(thinkMs) + 4000)
            );

            const bestMove = line.split(/\s+/)[1] || null;
            const whiteCp = turn === "w" ? scoreCp : -scoreCp;
            const whiteMate = mate === null ? null : (turn === "w" ? mate : -mate);

            return {
                cp: whiteCp,
                mate: whiteMate,
                depth,
                bestMove
            };
        } finally {
            lineHandlers.delete(listener);
        }
    }

    function close() {
        if (closed) {
            return;
        }

        closed = true;
        rejectAll(
            new Error("Stockfish engine closed.")
        );

        try {
            child.stdin.write("quit\n");
        } catch (error) {
            // The process may already be gone.
        }

        child.kill();
    }

    return {
        initialize,
        bestMove,
        analyzePosition,
        close
    };
}

async function chooseBotMove(game) {
    const legalMoves =
        game.chess.moves({ verbose: true });

    if (legalMoves.length === 0) {
        return null;
    }

    const config =
        BOT_CONFIGS[game.botDifficulty] ||
        BOT_CONFIGS.club1000;

    if (!config.stockfishRequired) {
        return fallbackBotMove(
            game.chess,
            game.botDifficulty
        );
    }

    if (game.botEngineFailed) {
        throw new Error(
            "Stockfish is unavailable for this bot."
        );
    }

    try {
        if (!game.botEngine) {
            game.botEngine =
                createStockfishEngine(
                    config
                );

            await game.botEngine.initialize();
        }

        const choice =
            await game.botEngine.bestMove(
                game.chess.fen(),
                config
            );

        if (choice) {
            return choice;
        }

        throw new Error(
            "Stockfish did not return a legal move."
        );
    } catch (error) {
        console.error(
            "Stockfish bot failed:",
            error.message
        );

        game.botEngine?.close();
        game.botEngine = null;
        game.botEngineFailed = true;

        throw error;
    }
}

async function executeBotMove(game) {
    if (
        !game ||
        game.gameOver ||
        !games.has(game.roomId) ||
        game.currentTurn !== "black"
    ) {
        return;
    }

    updateActiveClock(game);

    const choice =
        await chooseBotMove(game);

    if (!choice) {
        return;
    }

    const result = game.chess.move({
        from: choice.from,
        to: choice.to,
        promotion:
            choice.promotion || "q"
    });

    if (game.incrementMs > 0) {
        game.blackTime += game.incrementMs;
    }

    const from =
        squareToCoordinates(result.from);

    io.to(game.roomId).emit(
        "opponent-move",
        {
            fromY: from.y,
            fromX: from.x,
            move: normalizeNetworkMove(result),
            fen: game.chess.fen()
        }
    );

    game.currentTurn =
        chessToColor(
            game.chess.turn()
        );

    game.lastMoveTime = Date.now();

    io.to(game.roomId).emit(
        "position-sync",
        {
            fen: game.chess.fen()
        }
    );

    if (game.chess.isCheckmate()) {
        await finalizeGame(game, {
            reason: "checkmate",
            winner: "black"
        });
        return;
    }

    if (game.chess.isStalemate()) {
        await finalizeGame(game, {
            reason: "stalemate",
            winner: null
        });
        return;
    }

    if (game.chess.isDraw()) {
        await finalizeGame(game, {
            reason: getDrawReason(game.chess),
            winner: null
        });
        return;
    }

    io.to(game.roomId).emit(
        "turn-changed",
        game.currentTurn
    );

    sendClock(game);
    scheduleTimeout(game);
}

function scheduleBotMove(game) {
    if (game.botTimeoutId !== null) {
        clearTimeout(game.botTimeoutId);
    }

    game.botTimeoutId = setTimeout(
        function() {
            executeBotMove(game).catch(
                function(error) {
                    console.error(
                        "Bot move failed:",
                        error
                    );

                    io.to(game.roomId).emit(
                        "bot-engine-error",
                        {
                            error:
                                "The chess engine stopped unexpectedly. Start a new bot game."
                        }
                    );

                    removeGame(
                        game.roomId
                    );
                }
            );
        },
        550 + Math.floor(Math.random() * 350)
    );
}

async function processMove(socket, data) {
    const roomId = socket.data.roomId;

    if (!roomId) {
        return;
    }

    const game = games.get(roomId);

    if (!game || game.gameOver) {
        return;
    }

    const playerColor = socket.data.color;

    if (
        playerColor !== game.currentTurn ||
        colorToChess(playerColor) !==
            game.chess.turn()
    ) {
        return;
    }

    if (
        !data ||
        typeof data !== "object" ||
        !data.move ||
        typeof data.move !== "object"
    ) {
        return;
    }

    const coordinates = [
        data.fromY,
        data.fromX,
        data.move.y,
        data.move.x
    ];

    const validCoordinates =
        coordinates.every(function(value) {
            return (
                Number.isInteger(value) &&
                value >= 0 &&
                value <= 7
            );
        });

    if (!validCoordinates) {
        return;
    }

    updateActiveClock(game);

    const playerTime =
        playerColor === "white"
            ? game.whiteTime
            : game.blackTime;

    if (playerTime <= 0) {
        sendClock(game);

        await finalizeGame(game, {
            reason: "timeout",
            winner: oppositeColor(playerColor)
        });

        return;
    }

    const from =
        coordinatesToSquare(
            data.fromY,
            data.fromX
        );

    const to =
        coordinatesToSquare(
            data.move.y,
            data.move.x
        );

    const promotionMap = {
        queen: "q",
        rook: "r",
        bishop: "b",
        knight: "n"
    };

    let moveResult;

    try {
        moveResult = game.chess.move({
            from,
            to,
            promotion:
                promotionMap[
                    data.move.promotion
                ] || "q"
        });
    } catch (error) {
        socket.emit("move-rejected", {
            reason: "Illegal move."
        });
        return;
    }

    if (!moveResult) {
        socket.emit("move-rejected", {
            reason: "Illegal move."
        });
        return;
    }

    const normalizedMove =
        normalizeNetworkMove(moveResult);

    if (game.incrementMs > 0) {
        if (playerColor === "white") {
            game.whiteTime += game.incrementMs;
        } else {
            game.blackTime += game.incrementMs;
        }
    }

    socket.to(roomId).emit(
        "opponent-move",
        {
            fromY: data.fromY,
            fromX: data.fromX,
            move: normalizedMove,
            fen: game.chess.fen()
        }
    );

    game.currentTurn =
        chessToColor(
            game.chess.turn()
        );

    game.lastMoveTime = Date.now();

    io.to(roomId).emit(
        "position-sync",
        {
            fen: game.chess.fen()
        }
    );

    if (game.chess.isCheckmate()) {
        await finalizeGame(game, {
            reason: "checkmate",
            winner: playerColor
        });
        return;
    }

    if (game.chess.isStalemate()) {
        await finalizeGame(game, {
            reason: "stalemate",
            winner: null
        });
        return;
    }

    if (game.chess.isDraw()) {
        await finalizeGame(game, {
            reason: getDrawReason(game.chess),
            winner: null
        });
        return;
    }

    io.to(roomId).emit(
        "turn-changed",
        game.currentTurn
    );

    sendClock(game);

    if (
        game.mode === "bot" &&
        game.currentTurn === "black"
    ) {
        scheduleBotMove(game);
    } else {
        scheduleTimeout(game);
    }
}

function generatePrivateCode() {
    const alphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    let code = "";

    do {
        code = "";

        for (let i = 0; i < 6; i++) {
            code += alphabet[
                Math.floor(
                    Math.random() *
                    alphabet.length
                )
            ];
        }
    } while (privateWaiting.has(code));

    return code;
}

function removeSocketFromQueues(socket) {
    for (const [key, queuedSocket] of waitingPlayers.entries()) {
        if (queuedSocket?.id === socket.id) {
            waitingPlayers.delete(key);
        }
    }

    const privateCode =
        socket.data.privateCode;

    const privateEntry =
        privateCode
            ? privateWaiting.get(privateCode)
            : null;

    if (
        privateCode &&
        privateEntry?.socket?.id === socket.id
    ) {
        privateWaiting.delete(privateCode);
    }

    socket.data.privateCode = null;
}

function allowSocketAction(
    socket,
    key,
    limit,
    windowMs
) {
    const now = Date.now();

    if (!socket.data.rateLimits) {
        socket.data.rateLimits = {};
    }

    const current =
        socket.data.rateLimits[key];

    if (
        !current ||
        now - current.startedAt >= windowMs
    ) {
        socket.data.rateLimits[key] = {
            startedAt: now,
            count: 1
        };

        return true;
    }

    if (current.count >= limit) {
        return false;
    }

    current.count += 1;
    return true;
}


async function resumeGameForSocket(socket, user) {
    if (!user) {
        return false;
    }

    for (const game of games.values()) {
        if (game.gameOver) {
            continue;
        }

        let color = null;

        if (String(game.whiteUserId || "") === String(user.id)) {
            color = "white";
        } else if (String(game.blackUserId || "") === String(user.id)) {
            color = "black";
        }

        if (!color) {
            continue;
        }

        const socketKey = color === "white" ? "whiteSocketId" : "blackSocketId";
        const existing = getSocket(game[socketKey]);

        if (existing && existing.connected) {
            continue;
        }

        game[socketKey] = socket.id;
        socket.data.roomId = game.roomId;
        socket.data.color = color;
        socket.join(game.roomId);

        if (game.reconnectTimeouts?.[color]) {
            clearTimeout(game.reconnectTimeouts[color]);
            game.reconnectTimeouts[color] = null;
        }

        game.disconnectCounts[color] = 0;

        game.lastMoveTime = Date.now();

        socket.emit("match-found", {
            ...matchPayload(game, color),
            resume: true
        });

        socket.to(game.roomId).emit("opponent-reconnected", { color });
        sendClock(game);

        if (game.mode === "bot" && game.currentTurn === "black") {
            scheduleBotMove(game);
        } else {
            scheduleTimeout(game);
        }

        return true;
    }

    return false;
}

function findActiveGameForUserId(userId) {
    for (const game of games.values()) {
        if (game.gameOver) {
            continue;
        }

        if (
            String(game.whiteUserId || "") === String(userId) ||
            String(game.blackUserId || "") === String(userId)
        ) {
            return game;
        }
    }

    return null;
}

// Connections

io.on("connection", function(socket) {
    console.log(
        "Player connected:",
        socket.id
    );

    socketUser(socket)
        .then(async function(user) {
            if (user) {
                socket.join(
                    `user:${user.id}`
                );
                await resumeGameForSocket(socket, user);
            }
        })
        .catch(function(error) {
            console.error(
                "Social socket setup failed:",
                error
            );
        });

    socket.on("find-match", async function(payload = {}) {
        try {
            if (
                !allowSocketAction(
                    socket,
                    "matchmaking",
                    8,
                    10 * 1000
                )
            ) {
                socket.emit("matchmaking-error", {
                    error: "Too many matchmaking requests. Slow down."
                });
                return;
            }

            const user = await socketUser(socket);

            if (!user) {
                socket.emit("auth-required");
                return;
            }

            if (socket.data.roomId) {
                return;
            }

            removeSocketFromQueues(socket);

            const timeControlKey = normalizeTimeControlKey(payload?.timeControl);
            const queueKey = timeControlKey;
            const waitingPlayer = waitingPlayers.get(queueKey);

            if (
                waitingPlayer &&
                waitingPlayer.connected &&
                waitingPlayer.id !== socket.id
            ) {
                waitingPlayers.delete(queueKey);
                const opponent = waitingPlayer;

                const game = await createHumanGame(
                    opponent,
                    socket,
                    "quick",
                    timeControlKey
                );

                if (!game) {
                    socket.emit("auth-required");
                    return;
                }

                opponent.emit("match-found", matchPayload(game, "white"));
                socket.emit("match-found", matchPayload(game, "black"));

                sendClock(game);
                scheduleTimeout(game);

                console.log("Match created:", game.roomId, game.timeControlLabel);
                return;
            }

            waitingPlayers.set(queueKey, socket);
            socket.data.queueKey = queueKey;
            socket.emit("waiting-for-player", {
                timeControlKey,
                label: getTimeControl(timeControlKey).label
            });
        } catch (error) {
            console.error("Matchmaking failed:", error);
            socket.emit("matchmaking-error", {
                error: "Could not start matchmaking."
            });
        }
    });

    socket.on("cancel-match", function() {
        removeSocketFromQueues(socket);
    });

    socket.on("play-bot", async function(payload = {}) {
        try {
            if (
                !allowSocketAction(
                    socket,
                    "bot",
                    6,
                    10 * 1000
                )
            ) {
                socket.emit("matchmaking-error", {
                    error: "Too many bot requests. Slow down."
                });
                return;
            }

            const user = await socketUser(socket);

            if (!user) {
                socket.emit("auth-required");
                return;
            }

            if (socket.data.roomId) {
                return;
            }

            const difficulty =
                BOT_CONFIGS[payload?.difficulty]
                    ? payload.difficulty
                    : "club1000";

            const timeControlKey =
                normalizeTimeControlKey(
                    payload?.timeControl
                );

            const botConfig =
                BOT_CONFIGS[difficulty];

            if (botConfig.stockfishRequired) {
                try {
                    resolveStockfishEnginePath(
                        botConfig.engineFlavor
                    );
                } catch (error) {
                    socket.emit(
                        "matchmaking-error",
                        {
                            error:
                                "Stockfish is not installed. Run npm.cmd install, restart the server, then try again."
                        }
                    );
                    return;
                }
            }

            removeSocketFromQueues(socket);

            const game =
                await createBotGame(
                    socket,
                    difficulty,
                    timeControlKey
                );

            if (!game) {
                socket.emit("auth-required");
                return;
            }

            if (botConfig.stockfishRequired) {
                try {
                    game.botEngine =
                        createStockfishEngine(
                            botConfig
                        );

                    await game.botEngine
                        .initialize();

                    console.log(
                        `Stockfish ready for ${botConfig.name} (${botConfig.rating})`
                    );
                } catch (error) {
                    console.error(
                        "Could not initialize Stockfish:",
                        error.message
                    );

                    removeGame(
                        game.roomId
                    );

                    socket.emit(
                        "matchmaking-error",
                        {
                            error:
                                "Stockfish could not start. Run npm.cmd install and restart the server."
                        }
                    );
                    return;
                }
            }

            socket.emit(
                "match-found",
                matchPayload(
                    game,
                    "white"
                )
            );

            sendClock(game);
            scheduleTimeout(game);
        } catch (error) {
            console.error(
                "Bot game failed:",
                error
            );

            socket.emit(
                "matchmaking-error",
                {
                    error:
                        "Could not start the bot game."
                }
            );
        }
    });

    socket.on("create-private", async function(payload = {}) {
        try {
            if (
                !allowSocketAction(
                    socket,
                    "private",
                    8,
                    30 * 1000
                )
            ) {
                socket.emit("private-error", {
                    error: "Too many room requests. Slow down."
                });
                return;
            }

            const user = await socketUser(socket);

            if (!user) {
                socket.emit("auth-required");
                return;
            }

            if (socket.data.roomId) {
                return;
            }

            removeSocketFromQueues(socket);

            const code =
                generatePrivateCode();

            privateWaiting.set(
                code,
                {
                    socket,
                    timeControlKey:
                        normalizeTimeControlKey(
                            payload?.timeControl
                        )
                }
            );

            socket.data.privateCode = code;

            socket.emit("private-created", {
                code
            });
        } catch (error) {
            console.error(
                "Private room creation failed:",
                error
            );
        }
    });

    socket.on("join-private", async function(rawCode) {
        try {
            if (
                !allowSocketAction(
                    socket,
                    "private-join",
                    12,
                    30 * 1000
                )
            ) {
                socket.emit("private-error", {
                    error: "Too many room attempts. Slow down."
                });
                return;
            }

            const user = await socketUser(socket);

            if (!user) {
                socket.emit("auth-required");
                return;
            }

            const code =
                String(rawCode || "")
                    .toUpperCase()
                    .trim();

            if (
                !/^[A-HJ-NP-Z2-9]{6}$/.test(code)
            ) {
                socket.emit("private-error", {
                    error: "Enter a valid 6-character room code."
                });
                return;
            }

            const hostEntry =
                privateWaiting.get(code);

            const host =
                hostEntry?.socket;

            if (
                !host ||
                !host.connected ||
                host.id === socket.id
            ) {
                socket.emit("private-error", {
                    error: "Room code not found."
                });
                return;
            }

            privateWaiting.delete(code);
            host.data.privateCode = null;

            const game =
                await createHumanGame(
                    host,
                    socket,
                    "private",
                    hostEntry.timeControlKey
                );

            if (!game) {
                socket.emit("auth-required");
                return;
            }

            host.emit(
                "match-found",
                matchPayload(
                    game,
                    "white"
                )
            );

            socket.emit(
                "match-found",
                matchPayload(
                    game,
                    "black"
                )
            );

            sendClock(game);
            scheduleTimeout(game);
        } catch (error) {
            console.error(
                "Private join failed:",
                error
            );

            socket.emit("private-error", {
                error: "Could not join room."
            });
        }
    });

    socket.on("make-move", function(data) {
        if (
            !allowSocketAction(
                socket,
                "move",
                30,
                10 * 1000
            )
        ) {
            return;
        }

        processMove(socket, data).catch(
            function(error) {
                console.error(
                    "Move processing failed:",
                    error
                );
            }
        );
    });

    socket.on("resign", function() {
        const roomId = socket.data.roomId;

        if (!roomId) {
            return;
        }

        const game = games.get(roomId);

        if (!game || game.gameOver) {
            return;
        }

        finalizeGame(game, {
            reason: "resignation",
            winner:
                oppositeColor(
                    socket.data.color
                )
        }).catch(function(error) {
            console.error(
                "Resignation failed:",
                error
            );
        });
    });

    socket.on("offer-draw", function() {
        const roomId = socket.data.roomId;
        const game = roomId ? games.get(roomId) : null;

        if (!game || game.gameOver || game.mode === "bot") {
            return;
        }

        if (socket.data.color !== "white" && socket.data.color !== "black") {
            return;
        }

        if (game.drawOfferFrom) {
            return;
        }

        game.drawOfferFrom = socket.data.color;

        const opponentSocketId =
            socket.data.color === "white"
                ? game.blackSocketId
                : game.whiteSocketId;

        getSocket(opponentSocketId)?.emit("draw-offered", {
            from: socket.data.color
        });
        socket.emit("draw-offer-sent");
    });

    socket.on("respond-draw", function(rawAccepted) {
        const roomId = socket.data.roomId;
        const game = roomId ? games.get(roomId) : null;

        if (!game || game.gameOver || !game.drawOfferFrom) {
            return;
        }

        if (game.drawOfferFrom === socket.data.color) {
            return;
        }

        const accepted = Boolean(rawAccepted);
        const offeredBy = game.drawOfferFrom;
        game.drawOfferFrom = null;

        if (accepted) {
            finalizeGame(game, {
                reason: "agreement",
                winner: null
            }).catch(function(error) {
                console.error("Draw agreement failed:", error);
            });
            return;
        }

        const offererSocketId =
            offeredBy === "white"
                ? game.whiteSocketId
                : game.blackSocketId;

        getSocket(offererSocketId)?.emit("draw-declined", {
            by: socket.data.color,
            offeredBy
        });
        socket.emit("draw-declined", {
            by: socket.data.color,
            offeredBy
        });
    });

    socket.on("spectate-user", async function(rawUsername) {
        try {
            const viewer = await socketUser(socket);
            if (!viewer) {
                socket.emit("auth-required");
                return;
            }

            const target = await getUserByUsername(
                String(rawUsername || "").trim().slice(0, 20)
            );

            if (!target) {
                socket.emit("spectate-error", { error: "Player not found." });
                return;
            }

            const game = findActiveGameForUserId(target.id);
            if (!game) {
                socket.emit("spectate-error", { error: "That player is not in a live game." });
                return;
            }

            if (game.mode === "private") {
                const friendship = await getFriendship(viewer.id, target.id);
                if (!friendship || friendship.status !== "accepted") {
                    socket.emit("spectate-error", { error: "Private games can only be watched by friends." });
                    return;
                }
            }

            socket.join(game.roomId);
            socket.data.spectatingRoomId = game.roomId;
            socket.data.color = "spectator";

            socket.emit("spectate-started", {
                ...matchPayload(game, "white"),
                color: "spectator",
                mode: "spectate",
                originalMode: game.mode,
                rated: false
            });

            sendClock(game);
        } catch (error) {
            console.error("Spectate failed:", error);
            socket.emit("spectate-error", { error: "Could not spectate that game." });
        }
    });

    socket.on("leave-spectate", function() {
        const roomId = socket.data.spectatingRoomId;
        if (roomId) {
            socket.leave(roomId);
        }
        socket.data.spectatingRoomId = null;
        socket.data.color = null;
    });

    socket.on("emoji-reaction", function(rawEmoji) {
        const roomId = socket.data.roomId;

        if (!roomId) {
            return;
        }

        if (
            !allowSocketAction(
                socket,
                "emoji",
                10,
                5 * 1000
            )
        ) {
            return;
        }

        const game = games.get(roomId);

        if (!game || game.gameOver) {
            return;
        }

        const allowedEmojis = new Set([
            "ðŸ˜‚", "ðŸ˜­", "ðŸ”¥", "ðŸ’€", "ðŸ˜Ž",
            "ðŸ¤", "ðŸ‘", "â¤ï¸", "ðŸ˜¡", "ðŸ¤”",
            "ðŸ‘€", "ðŸŽ¯", "âš¡", "ðŸ‘‘", "ðŸ«¡",
            "ðŸ˜ˆ", "ðŸ¥¶", "ðŸ˜±", "ðŸ¤¯", "GG"
        ]);

        const emoji = String(rawEmoji || "").trim();

        if (!allowedEmojis.has(emoji)) {
            return;
        }

        socket.to(roomId).emit("emoji-reaction", {
            emoji,
            color: socket.data.color
        });
    });

    socket.on("chat-message", async function(message) {
        const roomId = socket.data.roomId;

        if (!roomId) {
            return;
        }

        if (
            !allowSocketAction(
                socket,
                "chat",
                8,
                8 * 1000
            )
        ) {
            socket.emit("chat-error", {
                error: "You are sending messages too quickly."
            });
            return;
        }

        if (typeof message !== "string") {
            return;
        }

        const cleanMessage =
            message
                .replace(/[\u0000-\u001f\u007f]/g, "")
                .replace(/\s+/g, " ")
                .trim()
                .slice(0, 150);

        if (cleanMessage.length === 0) {
            return;
        }

        if (containsBlockedContent(cleanMessage)) {
            socket.emit("chat-error", {
                error: "That message contains blocked language."
            });
            return;
        }

        const user = await socketUser(socket);

        io.to(roomId).emit(
            "chat-message",
            {
                sender:
                    user?.username ||
                    "Opponent",
                message: cleanMessage
            }
        );
    });

    // Client-reported game-over is intentionally ignored.
    // Chess.js on the server decides checkmate and draws.
    socket.on("game-over", function() {});

    socket.on("disconnect", function() {
        console.log("Player disconnected:", socket.id);
        removeSocketFromQueues(socket);

        if (socket.data.spectatingRoomId) {
            return;
        }

        const roomId = socket.data.roomId;
        if (!roomId) {
            return;
        }

        const game = games.get(roomId);
        if (!game || game.gameOver) {
            return;
        }

        const color = socket.data.color;
        if (color !== "white" && color !== "black") {
            return;
        }

        updateActiveClock(game);
        stopGameTimers(game);

        if (color === "white") {
            game.whiteSocketId = null;
        } else {
            game.blackSocketId = null;
        }

        game.disconnectCounts[color] = (game.disconnectCounts[color] || 0) + 1;

        if (game.disconnectCounts[color] >= 2) {
            finalizeGame(game, {
                reason: "disconnect",
                winner: oppositeColor(color)
            }).catch(function(error) {
                console.error("Repeat disconnect result failed:", error);
            });
            return;
        }

        io.to(roomId).emit("opponent-disconnected", {
            color,
            graceMs: RECONNECT_GRACE_MS
        });

        game.reconnectTimeouts[color] = setTimeout(function() {
            if (game.gameOver || !games.has(roomId)) {
                return;
            }

            const socketKey = color === "white" ? "whiteSocketId" : "blackSocketId";
            if (getSocket(game[socketKey])) {
                return;
            }

            finalizeGame(game, {
                reason: "disconnect",
                winner: oppositeColor(color)
            }).catch(function(error) {
                console.error("Disconnect result failed:", error);
            });
        }, RECONNECT_GRACE_MS);
    });
});

// Start Server

async function startServer() {
    await initializeDatabase();

    try {
        const result =
            await pool.query("SELECT NOW()");

        console.log(
            "Database connected:",
            result.rows[0].now
        );
    } catch (error) {
        console.error(
            "Database connection failed:",
            error
        );
    }

    try {
        const stockfishPath =
            resolveStockfishEnginePath(
                "full"
            );

        console.log(
            "Stockfish available:",
            path.basename(
                stockfishPath
            )
        );
    } catch (error) {
        console.warn(
            "Stockfish unavailable:",
            error.message
        );
    }

    server.listen(PORT, function() {
        console.log(
            `Pulse Chess server running on port ${PORT}`
        );
    });
}

startServer().catch(function(error) {
    console.error(
        "Pulse Chess failed to start:",
        error
    );
    process.exit(1);
});