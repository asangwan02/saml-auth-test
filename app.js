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

// Session setup
app.use(
  session({
    secret: SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: true
  })
);
app.use(passport.initialize());
app.use(passport.session());

// --- SAML strategy ---
passport.use(
  new SamlStrategy(
    {
      entryPoint: SAML_ENTRY_POINT,
      issuer: SAML_ISSUER,
      callbackUrl: SAML_CALLBACK_URL,
      cert: SAML_IDP_CERT
    },
    (profile, done) => done(null, profile)
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Serve static frontend (index.html)
app.use(express.static('public'));

// --- Routes ---
app.get('/login', passport.authenticate('saml', { failureRedirect: '/' }));

app.post(
  '/acs',
  passport.authenticate('saml', { failureRedirect: '/' }),
  (req, res) => res.redirect('/profile')
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login');
  res.send(
    `<h1>Profile</h1><pre>${JSON.stringify(
      req.user,
      null,
      2
    )}</pre><a href="/logout">Logout</a>`
  );
});

app.get('/logout', (req, res) => {
  req.logout(() => req.session.destroy(() => res.send('Logged out')));
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// Start server
app.listen(PORT, () =>
  console.log(`🚀 Server running on http://localhost:${PORT}`)
);
