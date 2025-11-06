// app.js
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const SamlStrategy = require('passport-saml').Strategy;

const {
  PORT = 3000,
  SESSION_SECRET,
  SAML_ENTRY_POINT,
  SAML_ISSUER,
  SAML_CALLBACK_URL,
  SAML_IDP_CERT
} = process.env;

const app = express();

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
app.post('/acs', (req, res, next) => {
  console.log('📥 Received POST /acs (SAML Response)');
  passport.authenticate('saml', (err, user, info) => {
    if (err) {
      console.error('❌ SAML Error:', err);
      return res
        .status(500)
        .send(`<h2>SAML Error</h2><pre>${err.message}</pre>`);
    }
    if (!user) {
      console.error('⚠️  No user returned from SAML.');
      return res
        .status(401)
        .send('<h2>Unauthorized: Invalid SAML response</h2>');
    }

    console.log('✅ User authenticated via SAML:', user.nameID);
    req.login(user, (loginErr) => {
      if (loginErr) {
        console.error('❌ Session login failed:', loginErr);
        return res.status(500).send('Internal server error after SAML login');
      }
      console.log('🔁 Redirecting to /profile');
      res.redirect('/profile');
    });
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
