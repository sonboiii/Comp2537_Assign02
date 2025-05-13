const express = require('express');
const session = require('express-session');
const connectMongo = require('connect-mongo');
const { MongoClient } = require('mongodb');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const path = require('path');

dotenv.config();

const app = express();
const port = process.env.PORT || 1001;

const mongoUrl = `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`;
const client = new MongoClient(mongoUrl);

const MongoStore = connectMongo.create({
  client: client,
  dbName: process.env.MONGODB_DATABASE,
  collectionName: 'sessions',
  crypto: { secret: process.env.MONGODB_SESSION_SECRET }
});

app.use(
  session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore,
    cookie: { maxAge: 60 * 60 * 1000 },
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

const isLoggedIn = (req, res, next) => {
  if (req.session.user) next();
  else res.redirect('/login');
};

const isAdmin = (req, res, next) => {
  if (req.session.user && req.session.user.user_type === 'admin') next();
  else res.status(403).render('403', { user: req.session.user });
};

async function home(req, res) {
  if (req.session.user) {
    res.render('home', {
      user: req.session.user,
      message: `Welcome, ${req.session.user.name}!`,
      membersLink: '/members',
      logoutLink: '/logout'
    });
  } else {
    res.render('home', {
      user: null,
      message: 'Please sign up or log in to continue.',
      signupLink: '/signup',
      loginLink: '/login'
    });
  }
}

async function signup(req, res) {
  res.render('signup', { user: null });
}

async function signupPost(req, res) {
  const schema = Joi.object({
    name: Joi.string().max(255).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const db = client.db(process.env.MONGODB_DATABASE);
  const users = db.collection('users');

  const existingUser = await users.findOne({ email: value.email });
  if (existingUser) return res.status(400).send('Email already exists');

  const hashedPassword = await bcrypt.hash(value.password, 10);
  const newUser = {
    name: value.name,
    email: value.email,
    password: hashedPassword,
    user_type: 'user'
  };

  await users.insertOne(newUser);
  req.session.user = { name: newUser.name, email: newUser.email, user_type: newUser.user_type };
  res.redirect('/members');
}

async function login(req, res) {
  res.render('login', { message: null, user: null });
}

async function loginPost(req, res) {
  const schema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required(),
  });
  const { error, value } = schema.validate(req.body);
  if (error) return res.status(400).send(error.details[0].message);

  const db = client.db(process.env.MONGODB_DATABASE);
  const users = db.collection('users');
  const user = await users.findOne({ email: value.email });

  if (!user || !(await bcrypt.compare(value.password, user.password))) {
    res.render('login', { message: 'Invalid email/password combination', user: null });
  }

  req.session.user = { name: user.name, email: user.email, user_type: user.user_type };
  res.redirect('/');
}

async function logout(req, res) {
  req.session.destroy(() => res.redirect('/'));
}

async function members(req, res) {
  if (!req.session.user) return res.redirect('/');
  const images = ['cat1.jpg', 'cat2.jpg', 'cat3.jpg'];
  res.render('members', { user: req.session.user, images });
}

async function admin(req, res) {
  const db = client.db(process.env.MONGODB_DATABASE);
  const users = await db.collection('users').find().toArray();
  res.render('admin', { user: req.session.user, users });
}

async function promote(req, res) {
  const db = client.db(process.env.MONGODB_DATABASE);
  await db.collection('users').updateOne({ email: req.body.email }, { $set: { user_type: 'admin' } });
  res.redirect('/admin');
}

async function demote(req, res) {
  const db = client.db(process.env.MONGODB_DATABASE);
  await db.collection('users').updateOne({ email: req.body.email }, { $set: { user_type: 'user' } });
  res.redirect('/admin');
}

function error404(req, res) {
  res.status(404).render('404', { user: req.session.user });
}

async function run() {
  try {
    await client.connect();
    console.log('Connected to MongoDB');

    app.get('/', home);
    app.get('/signup', signup);
    app.post('/signup', signupPost);
    app.get('/login', login);
    app.post('/login', loginPost);
    app.get('/logout', logout);
    app.get('/members', isLoggedIn, members);
    app.get('/admin', isLoggedIn, isAdmin, admin);
    app.post('/promote', isLoggedIn, isAdmin, promote);
    app.post('/demote', isLoggedIn, isAdmin, demote);
    app.use(error404);

    app.listen(port, () => console.log(`Server is running at http://localhost:${port}`));
  } catch (err) {
    console.error('MongoDB connection error:', err);
  }
}

run().catch(console.dir);
