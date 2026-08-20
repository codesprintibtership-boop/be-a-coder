 require("dotenv").config();

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";

const express = require("express");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = 3000;

// ==============================
// PATHS
// ==============================

const PUBLIC_DIR = path.join(__dirname, "public");
const UPLOAD_DIR = path.join(__dirname, "payment-screenshots");
const ACCOUNTS_FILE = path.join(__dirname, "accounts.json");
const SESSIONS_FILE = path.join(__dirname, "sessions.json");

// ==============================
// CREATE FILES / FOLDERS
// ==============================

if (!fs.existsSync(UPLOAD_DIR)) {
    fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

if (!fs.existsSync(ACCOUNTS_FILE)) {
    fs.writeFileSync(ACCOUNTS_FILE, "[]", "utf8");
}

if (!fs.existsSync(SESSIONS_FILE)) {
    fs.writeFileSync(SESSIONS_FILE, "[]", "utf8");
}

// ==============================
// EXPRESS
// ==============================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==============================
// JSON HELPERS
// ==============================

function readJSON(file) {
    try {
        return JSON.parse(
            fs.readFileSync(file, "utf8")
        );
    } catch {
        return [];
    }
}

function writeJSON(file, data) {
    fs.writeFileSync(
        file,
        JSON.stringify(data, null, 2),
        "utf8"
    );
}

// ==============================
// PAYMENT UPLOAD
// ==============================

const storage = multer.diskStorage({

    destination: function(req, file, cb) {
        cb(null, UPLOAD_DIR);
    },

    filename: function(req, file, cb) {

        const ext =
            path.extname(file.originalname);

        const name =
            "payment-" +
            Date.now() +
            "-" +
            crypto.randomBytes(4).toString("hex") +
            ext;

        cb(null, name);
    }

});

const upload = multer({

    storage: storage,

    limits: {
        fileSize: 5 * 1024 * 1024
    },

    fileFilter: function(req, file, cb) {

        if (
            file.mimetype &&
            file.mimetype.startsWith("image/")
        ) {
            cb(null, true);
        } else {
            cb(
                new Error(
                    "Only image files are allowed."
                )
            );
        }

    }

});

// ==============================
// GMAIL
// ==============================

const transporter =
    nodemailer.createTransport({

        service: "gmail",

        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_APP_PASSWORD
        }

    });

// ==============================
// OTP
// ==============================

const otpStore = new Map();

// ==============================
// ADMIN SESSION
// ==============================

const adminSessions = new Map();

function createAdminSession() {

    const token =
        crypto.randomBytes(32).toString("hex");

    adminSessions.set(
        token,
        Date.now() + 24 * 60 * 60 * 1000
    );

    return token;
}

function getAdminSession(req) {

    const cookie =
        req.headers.cookie || "";

    const match =
        cookie.match(
            /codesprint_admin=([^;]+)/
        );

    if (!match) {
        return null;
    }

    const token =
        decodeURIComponent(match[1]);

    const expiresAt =
        adminSessions.get(token);

    if (
        !expiresAt ||
        expiresAt <= Date.now()
    ) {

        adminSessions.delete(token);

        return null;
    }

    return token;
}

// ==============================
// STUDENT SESSION
// ==============================

function createSession(email) {

    const sessions =
        readJSON(SESSIONS_FILE);

    const token =
        crypto.randomBytes(32).toString("hex");

    const cleanSessions =
        sessions.filter(
            s =>
                s.expiresAt > Date.now()
        );

    cleanSessions.push({

        token: token,

        email: email,

        createdAt:
            new Date().toISOString(),

        expiresAt:
            Date.now() +
            30 * 24 * 60 * 60 * 1000

    });

    writeJSON(
        SESSIONS_FILE,
        cleanSessions
    );

    return token;
}

function getSession(req) {

    const cookie =
        req.headers.cookie || "";

    const match =
        cookie.match(
            /codesprint_session=([^;]+)/
        );

    if (!match) {
        return null;
    }

    const token =
        decodeURIComponent(match[1]);

    const sessions =
        readJSON(SESSIONS_FILE);

    return sessions.find(
        s =>
            s.token === token &&
            s.expiresAt > Date.now()
    ) || null;
}

// ==============================
// ADMIN LOGIN
// ==============================

app.post(
    "/api/admin-login",
    function(req, res) {

        const email =
            String(
                req.body.email || ""
            )
            .trim()
            .toLowerCase();

        const password =
            String(
                req.body.password || ""
            );

        if (
            !ADMIN_EMAIL ||
            !ADMIN_PASSWORD ||
            email !==
                ADMIN_EMAIL
                .trim()
                .toLowerCase() ||
            password !==
                ADMIN_PASSWORD
        ) {

            return res.status(401).json({

                success: false,

                message:
                    "Invalid admin credentials."

            });
        }

        const token =
            createAdminSession();

        res.setHeader(
            "Set-Cookie",
            `codesprint_admin=${encodeURIComponent(token)}; Max-Age=86400; Path=/; HttpOnly; SameSite=Lax`
        );

        return res.json({

            success: true,

            message:
                "Admin login successful."

        });

    }
);

// ==============================
// ADMIN LOGOUT
// ==============================

app.post(
    "/api/admin-logout",
    function(req, res) {

        const token =
            getAdminSession(req);

        if (token) {
            adminSessions.delete(token);
        }

        res.setHeader(
            "Set-Cookie",
            "codesprint_admin=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        );

        return res.json({
            success: true
        });

    }
);

// ==============================
// SEND OTP
// ==============================

app.post(
    "/api/send-otp",
    async function(req, res) {

        try {

            const email =
                String(
                    req.body.email || ""
                )
                .trim()
                .toLowerCase();

            if (
                !/^[^\s@]+@[^\s@]+\.[^\s@]+$/
                .test(email)
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter a valid email."

                });
            }

            const otp =
                String(
                    Math.floor(
                        100000 +
                        Math.random() *
                        900000
                    )
                );

            otpStore.delete(email);

            otpStore.set(
                email,
                {

                    otp: otp,

                    expires:
                        Date.now() +
                        5 * 60 * 1000

                }
            );

            console.log(
                "OTP for",
                email,
                ":",
                otp
            );

            await transporter.sendMail({

                from:
                    `"CodeSprint" <${process.env.EMAIL_USER}>`,

                to: email,

                subject:
                    "CodeSprint Login OTP",

                text:
                    `Your CodeSprint OTP is ${otp}.

This OTP is valid for 5 minutes.

Use the latest OTP if you requested a new one.`

            });

            res.json({

                success: true,

                message:
                    "OTP sent successfully."

            });

        } catch(error) {

            console.error(
                "SEND OTP ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Could not send OTP."

            });

        }

    }
);

// ==============================
// VERIFY OTP + CREATE ACCOUNT
// ==============================

app.post(
    "/api/verify-otp",
    function(req, res) {

        const email =
            String(
                req.body.email || ""
            )
            .trim()
            .toLowerCase();

        const otp =
            String(
                req.body.otp || ""
            )
            .trim();

        const saved =
            otpStore.get(email);

        if (!saved) {

            return res.status(400).json({

                success: false,

                verified: false,

                loggedIn: false,

                message:
                    "OTP not found. Please request a new OTP."

            });
        }

        if (
            Date.now() >
            saved.expires
        ) {

            otpStore.delete(email);

            return res.status(400).json({

                success: false,

                verified: false,

                loggedIn: false,

                message:
                    "OTP expired. Please request a new OTP."

            });
        }

        if (
            String(saved.otp) !==
            String(otp)
        ) {

            return res.status(400).json({

                success: false,

                verified: false,

                loggedIn: false,

                message:
                    "Incorrect OTP."

            });
        }

        otpStore.delete(email);

        const accounts =
            readJSON(ACCOUNTS_FILE);

        let account =
            accounts.find(
                a =>
                    a.email === email
            );

        if (!account) {

            account = {

                id:
                    crypto
                    .randomBytes(8)
                    .toString("hex"),

                email: email,

                emailVerified: true,

                createdAt:
                    new Date().toISOString(),

                registration: null

            };

            accounts.push(account);

        } else {

            account.emailVerified = true;

            account.lastLoginAt =
                new Date().toISOString();

        }

        writeJSON(
            ACCOUNTS_FILE,
            accounts
        );

        const token =
            createSession(email);

        res.setHeader(
            "Set-Cookie",

            `codesprint_session=${encodeURIComponent(token)}; Max-Age=2592000; Path=/; HttpOnly; SameSite=Lax`
        );

        res.json({

            success: true,

            verified: true,

            loggedIn: true,

            account: account,

            message:
                "Email verified and account ready."

        });

    }
);

// ==============================
// CURRENT ACCOUNT
// ==============================

app.get(
    "/api/me",
    function(req, res) {

        const session =
            getSession(req);

        if (!session) {

            return res.status(401).json({

                loggedIn: false

            });
        }

        const accounts =
            readJSON(ACCOUNTS_FILE);

        const account =
            accounts.find(
                a =>
                    a.email ===
                    session.email
            );

        if (!account) {

            return res.status(404).json({

                loggedIn: false

            });
        }

        res.json({

            loggedIn: true,

            account: account

        });

    }
);

// ==============================
// REGISTRATION
// ==============================

app.post(
    "/api/register",
    upload.single("paymentScreenshot"),
    function(req, res) {

        try {

            const session =
                getSession(req);

            if (!session) {

                if (req.file) {

                    fs.unlink(
                        req.file.path,
                        () => {}
                    );

                }

                return res.status(401).json({

                    success: false,

                    message:
                        "Please login before registering."

                });
            }

            const accounts =
                readJSON(ACCOUNTS_FILE);

            const account =
                accounts.find(
                    a =>
                        a.email ===
                        session.email
                );

            if (!account) {

                return res.status(404).json({

                    success: false,

                    message:
                        "Account not found."

                });
            }

            // Prevent duplicate registration
            if (
                account.registration &&
                account.registration.registrationStatus ===
                    "Completed"
            ) {

                if (req.file) {

                    fs.unlink(
                        req.file.path,
                        () => {}
                    );

                }

                return res.status(400).json({

                    success: false,

                    message:
                        "You are already registered."

                });
            }

            const registration = {

                name:
                    String(
                        req.body.name || ""
                    ).trim(),

                email:
                    session.email,

                mobile:
                    String(
                        req.body.mobile || ""
                    ).trim(),

                college:
                    String(
                        req.body.college || ""
                    ).trim(),

                year:
                    String(
                        req.body.year || ""
                    ).trim(),

                branch:
                    String(
                        req.body.branch || ""
                    ).trim(),

                about:
                    String(
                        req.body.about || ""
                    ).trim(),

                referral:
                    String(
                        req.body.referral || ""
                    ).trim(),

                utr:
                    String(
                        req.body.utr || ""
                    ).trim(),

                paymentScreenshot:
                    req.file
                    ? req.file.filename
                    : null,

                paymentStatus:
                    "Submitted",

                registrationStatus:
                    "Completed",

                registeredAt:
                    new Date().toISOString()

            };

            // ==========================
            // VALIDATION
            // ==========================

            if (
                !registration.name ||
                !registration.mobile ||
                !registration.college ||
                !registration.year ||
                !registration.branch
            ) {

                if (req.file) {

                    fs.unlink(
                        req.file.path,
                        () => {}
                    );

                }

                return res.status(400).json({

                    success: false,

                    message:
                        "Please fill all required fields."

                });
            }

            if (!registration.utr) {

                if (req.file) {

                    fs.unlink(
                        req.file.path,
                        () => {}
                    );

                }

                return res.status(400).json({

                    success: false,

                    message:
                        "Please enter UTR / Transaction ID."

                });
            }

            if (!registration.paymentScreenshot) {

                return res.status(400).json({

                    success: false,

                    message:
                        "Please upload payment screenshot."

                });
            }

            // ==========================
            // SAVE
            // ==========================

            account.registration =
                registration;

            account.updatedAt =
                new Date().toISOString();

            writeJSON(
                ACCOUNTS_FILE,
                accounts
            );

            console.log(
                "REGISTRATION SAVED:",
                session.email
            );

            // ==========================
            // ADMIN EMAIL
            // ==========================

            transporter.sendMail({

                from:
                    `"CodeSprint" <${process.env.EMAIL_USER}>`,

                to:
                    process.env.EMAIL_USER,

                subject:
                    `New Registration - ${registration.name}`,

                text:
                    `New CodeSprint registration.

Name: ${registration.name}
Email: ${registration.email}
Mobile: ${registration.mobile}
College: ${registration.college}
Year: ${registration.year}
Branch: ${registration.branch}
UTR: ${registration.utr}

Payment screenshot:
${registration.paymentScreenshot}`

            }).catch(
                error =>
                    console.error(
                        "ADMIN EMAIL ERROR:",
                        error
                    )
            );

            res.json({

                success: true,

                message:
                    "Registration saved to your account.",

                account:
                    account

            });

        } catch(error) {

            console.error(
                "REGISTRATION ERROR:",
                error
            );

            res.status(500).json({

                success: false,

                message:
                    "Registration failed."

            });

        }

    }
);

// ==============================
// ADMIN — ALL STUDENTS
// ==============================

app.get(
    "/api/admin/students",
    function(req, res) {

        const adminSession =
            getAdminSession(req);

        if (!adminSession) {

            return res.status(401).json({

                success: false,

                message:
                    "Admin login required."

            });
        }

        const accounts =
            readJSON(ACCOUNTS_FILE);

        return res.json({

            success: true,

            students:
                accounts

        });

    }
);

// ==============================
// ADMIN — PAYMENT SCREENSHOT
// ==============================

app.get(
    "/api/admin/payment/:filename",
    function(req, res) {

        const adminSession =
            getAdminSession(req);

        if (!adminSession) {

            return res.status(401).send(
                "Admin login required."
            );
        }

        const filename =
            path.basename(
                String(
                    req.params.filename || ""
                )
            );

        const filePath =
            path.join(
                UPLOAD_DIR,
                filename
            );

        if (!fs.existsSync(filePath)) {

            return res.status(404).send(
                "Screenshot not found."
            );
        }

        return res.sendFile(filePath);

    }
);

// ==============================
// STUDENT LOGOUT
// ==============================

app.post(
    "/api/logout",
    function(req, res) {

        const session =
            getSession(req);

        if (session) {

            const sessions =
                readJSON(SESSIONS_FILE);

            const remaining =
                sessions.filter(
                    s =>
                        s.token !==
                        session.token
                );

            writeJSON(
                SESSIONS_FILE,
                remaining
            );

        }

        res.setHeader(
            "Set-Cookie",
            "codesprint_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax"
        );

        res.json({

            success: true

        });

    }
);

// ==============================
// PROTECTED PAYMENT FILES
// ==============================

// IMPORTANT:
// Do NOT use express.static() for
// payment-screenshots here.
// They are accessible only through
// /api/admin/payment/:filename

// ==============================
// PUBLIC WEBSITE
// ==============================

app.use(
    express.static(PUBLIC_DIR)
);

// ==============================
// GMAIL CHECK
// ==============================

transporter.verify(
    function(error) {

        if (error) {

            console.log(
                "GMAIL CONNECTION ERROR:"
            );

            console.log(error);

        } else {

            console.log(
                "GMAIL CONNECTION SUCCESS!"
            );

        }

    }
);

// ==============================
// START SERVER
// ==============================

app.listen(
    PORT,
    function() {

        console.log(
            `CodeSprint running at http://localhost:${PORT}`
        );

    }
);