// app.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const {
  PORT = 3000,
  SESSION_SECRET,
  SAML_ENTRY_POINT,
  SAML_ISSUER,
  SAML_CALLBACK_URL,
  SAML_IDP_CERT
} = process.env;

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));

// --- Middleware logging ---
app.use((req, res, next) => {
  console.log(`➡️  ${req.method} ${req.url}`);
  next();
});

// --- Session setup ---
app.use(
  session({
    secret: SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: true
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --- Initialize SAML Strategy ---
console.log('⚙️  Initializing SAML Strategy...');
console.log('🔹 EntryPoint:', SAML_ENTRY_POINT);
console.log('🔹 Issuer:', SAML_ISSUER);
console.log('🔹 Callback URL:', SAML_CALLBACK_URL);
console.log('🔹 Certificate length:', SAML_IDP_CERT?.length || 0);

passport.use(
  new SamlStrategy(
    {
      entryPoint: SAML_ENTRY_POINT,
      issuer: SAML_ISSUER,
      callbackUrl: SAML_CALLBACK_URL,
      cert: SAML_IDP_CERT
    },
    (profile, done) => {
      console.log('✅ SAML Authentication succeeded.');
      console.log('👤 User Profile:', profile?.nameID || '[no nameID]');
      done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => {
  console.log('🔒 Serializing user:', user?.nameID || '[unknown]');
  done(null, user);
});

passport.deserializeUser((user, done) => {
  console.log('🔓 Deserializing user:', user?.nameID || '[unknown]');
  done(null, user);
});

// --- Serve frontend ---
app.use(express.static('public'));

// --- Routes ---
app.get('/login', (req, res, next) => {
  console.log('🚀 /login triggered → Redirecting to IdP');
  passport.authenticate('saml', { failureRedirect: '/' })(req, res, next);
});

// --- Assertion Consumer Service (ACS) ---
app.post('/auth/login/saml/assertion', (req, res, next) => {
  console.log('📥 Received POST /acs (SAML Response)');
  console.log('🧾 Headers:', JSON.stringify(req.headers, null, 2));
  console.log('🧩 Checking request body...');

  // In case body parsing fails
  if (!req.body) {
    console.error(
      '❌ No body found in request — make sure body-parser is enabled!'
    );
    return res.status(400).json({ error: 'Missing request body' });
  }

  // Log the beginning of the SAMLResponse for inspection (safe truncation)
  if (req.body.SAMLResponse) {
    console.log(
      '📦 Raw SAMLResponse (truncated):',
      req.body.SAMLResponse.substring(0, 200) + '...'
    );
  } else {
    console.error('⚠️  Missing SAMLResponse field in request body');
  }

  // Passport SAML verification
  passport.authenticate('saml', (err, user, info) => {
    console.log('🔹 Inside passport.authenticate callback');

    if (err) {
      console.error('❌ SAML Error:', err);
      return res.status(500).json({
        error: 'SAML processing failed',
        details: err.message
      });
    }

    if (!user) {
      console.error(
        '⚠️  No user returned from SAML (check certificate, ACS URL, or NameID format)'
      );
      return res.status(401).json({
        error: 'Unauthorized - invalid or missing SAML response'
      });
    }

    console.log('✅ SAML Authenticated User:', user.nameID);
    console.log('🧠 Full user object:', JSON.stringify(user, null, 2));

    // Create internal JWT
    try {
      const tokenPayload = {
        email: user.nameID,
        attributes: user,
        iat: Math.floor(Date.now() / 1000)
      };

      const token = jwt.sign(tokenPayload, 'process.env.INTERNAL_JWT_SECRET', {
        expiresIn: '1h'
      });

      console.log('🎟️ JWT successfully created for:', user.nameID);
      console.log('🔁 Sending JSON response to client');

      return res.status(200).json({
        message: 'SAML authentication successful',
        user: {
          email: user.nameID,
          attributes: user
        },
        token
      });
    } catch (tokenErr) {
      console.error('❌ JWT creation failed:', tokenErr);
      return res.status(500).json({
        error: 'Internal error while creating token',
        details: tokenErr.message
      });
    }
  })(req, res, next);
});

// --- Protected profile page ---
app.get('/profile', (req, res) => {
  console.log('👤 Accessing /profile');
  if (!req.isAuthenticated()) {
    console.warn('⚠️  Unauthorized access to /profile → Redirecting to /login');
    return res.redirect('/login');
  }

  console.log('✅ Authenticated user:', req.user?.nameID || '[unknown]');
  res.send(
    `<h1>Profile</h1><pre>${JSON.stringify(
      req.user,
      null,
      2
    )}</pre><a href="/logout">Logout</a>`
  );
});

// --- Logout ---
app.get('/logout', (req, res) => {
  console.log('🚪 Logging out user...');
  req.logout(() => {
    req.session.destroy(() => {
      console.log('✅ Session destroyed. User logged out.');
      res.send('Logged out');
    });
  });
});

// --- Root route ---
app.get('/', (req, res) => {
  console.log('🌐 Serving index.html');
  res.sendFile(__dirname + '/public/index.html');
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
