const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const bcrypt = require("bcrypt");

const app = express();

const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || "lifefit";
const FRONTEND_URL =
  process.env.FRONTEND_URL || "https://carvalhodevmax.github.io";
const TERMS_VERSION = "1.0";

if (!MONGODB_URI || !process.env.SESSION_SECRET) {
  throw new Error("Configure MONGODB_URI e SESSION_SECRET no Render.");
}

let client;
let db;
let storage;
let users;

async function connectDB() {
  if (db) return db;

  client = new MongoClient(MONGODB_URI);
  await client.connect();

  db = client.db(DB_NAME);
  storage = db.collection("storage");
  users = db.collection("users");

  await Promise.all([
    storage.createIndex(
      { key: 1, shared: 1, clientId: 1 },
      { unique: true }
    ),
    users.createIndex({ email: 1 }, { unique: true }),
    users.createIndex({ googleId: 1 }, { unique: true, sparse: true }),
    users.createIndex({ facebookId: 1 }, { unique: true, sparse: true })
  ]);

  console.log(`MongoDB conectado: ${DB_NAME}`);
  return db;
}

app.set("trust proxy", 1);

app.use(helmet({ crossOriginResourcePolicy: false }));

app.use(
  cors({
    origin: new URL(FRONTEND_URL).origin,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "lifefit.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: MONGODB_URI,
      dbName: DB_NAME,
      ttl: 60 * 60 * 24 * 14
    }),
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
      maxAge: 1000 * 60 * 60 * 24 * 14
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user._id.toString());
});

passport.deserializeUser(async (id, done) => {
  try {
    await connectDB();
    const user = await users.findOne({
      _id: new ObjectId(id)
    });
    done(null, user);
  } catch (error) {
    done(error);
  }
});

function emailOf(value) {
  return String(value || "").trim().toLowerCase();
}

function publicUser(user) {
  return {
    id: user._id.toString(),
    name: user.name,
    email: user.email,
    avatarUrl: user.avatarUrl || null,
    provider: user.provider,
    termsVersion: user.termsVersion,
    profile: user.profile || {}
  };
}

function redirectFrontend(res, params) {
  res.redirect(`${FRONTEND_URL}?${new URLSearchParams(params)}`);
}

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

async function resolveOAuthUser(provider, profile, req) {
  await connectDB();

  const email = emailOf(profile.emails?.[0]?.value);
  const providerId = profile.id;
  const idField = provider === "google" ? "googleId" : "facebookId";
  const avatarUrl = profile.photos?.[0]?.value || null;
  const intent = req.session.oauthIntent || {};

  if (!email) throw new Error("EMAIL_REQUIRED");

  const socialUser = await users.findOne({
    [idField]: providerId
  });

  if (intent.link) {
    if (!intent.userId) throw new Error("LOGIN_REQUIRED");

    const owner = await users.findOne({
      _id: new ObjectId(intent.userId)
    });

    if (!owner) throw new Error("LOGIN_REQUIRED");

    if (
      socialUser &&
      socialUser._id.toString() !== owner._id.toString()
    ) {
      throw new Error("PROVIDER_ALREADY_LINKED");
    }

    if (owner.email !== email) {
      throw new Error("LINK_EMAIL_MISMATCH");
    }

    if (!socialUser) {
      await users.updateOne(
        { _id: owner._id },
        {
          $set: {
            [idField]: providerId,
            avatarUrl: owner.avatarUrl || avatarUrl,
            updatedAt: new Date()
          },
          $addToSet: {
            providers: {
              provider,
              providerId,
              linkedAt: new Date()
            }
          }
        }
      );
    }

    return users.findOne({ _id: owner._id });
  }

  if (socialUser) return socialUser;

  const existing = await users.findOne({ email });

  if (existing) {
    throw new Error("ACCOUNT_LINK_REQUIRED");
  }

  if (!intent.termsAccepted) {
    throw new Error("TERMS_REQUIRED");
  }

  const user = {
    name: profile.displayName || email.split("@")[0],
    email,
    avatarUrl,
    provider,
    [idField]: providerId,
    providers: [
      {
        provider,
        providerId,
        linkedAt: new Date()
      }
    ],
    termsAccepted: true,
    termsAcceptedAt: new Date(),
    termsVersion: TERMS_VERSION,
    profile: {},
    createdAt: new Date(),
    updatedAt: new Date()
  };

  const result = await users.insertOne(user);
  user._id = result.insertedId;

  return user;
}

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        done(null, await resolveOAuthUser("google", profile, req));
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  "facebook",
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["id", "displayName", "emails", "photos"],
      passReqToCallback: true
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        done(null, await resolveOAuthUser("facebook", profile, req));
      } catch (error) {
        done(error);
      }
    }
  )
);

function startOAuth(provider) {
  return (req, res, next) => {
    const link = req.query.link === "1";

    if (link && !req.user) {
      return redirectFrontend(res, {
        auth_error: "LOGIN_REQUIRED"
      });
    }

    req.session.oauthIntent = {
      link,
      userId: link ? req.user._id.toString() : null,
      termsAccepted:
        req.query.signup === "1" &&
        req.query.termsAccepted === "1"
    };

    req.session.save((error) => {
      if (error) return next(error);

      passport.authenticate(provider, {
        scope: provider === "google" ? ["profile", "email"] : ["email"],
        state: true
      })(req, res, next);
    });
  };
}

["google", "facebook"].forEach((provider) => {
  app.get(`/api/auth/${provider}`, startOAuth(provider));

  app.get(
    `/api/auth/${provider}/callback`,
    (req, res, next) => {
      passport.authenticate(provider, (error, user) => {
        if (error || !user) {
          return redirectFrontend(res, {
            auth_error: error ? error.message : "OAUTH_FAILED",
            provider
          });
        }

        req.logIn(user, (loginError) => {
          if (loginError) return next(loginError);

          delete req.session.oauthIntent;

          redirectFrontend(res, {
            auth_success: provider
          });
        });
      })(req, res, next);
    }
  );
});

app.post("/api/auth/register", loginLimiter, async (req, res, next) => {
  try {
    await connectDB();

    const name = String(req.body.name || "").trim();
    const email = emailOf(req.body.email);
    const password = req.body.password;
    const profile = req.body.profile || {};

    if (
      !name ||
      !/^\S+@\S+\.\S+$/.test(email) ||
      typeof password !== "string" ||
      password.length < 8
    ) {
      return res.status(400).json({
        error: "Dados de cadastro inválidos."
      });
    }

    if (req.body.termsAccepted !== true) {
      return res.status(400).json({
        error:
          "Você precisa aceitar os Termos de Uso e a Política de Privacidade."
      });
    }

    if (await users.findOne({ email })) {
      return res.status(409).json({
        error: "Este e-mail já possui uma conta no LifeFIT."
      });
    }

    const user = {
      name,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      provider: "local",
      providers: [],
      termsAccepted: true,
      termsAcceptedAt: new Date(),
      termsVersion: TERMS_VERSION,
      profile,
      createdAt: new Date(),
      updatedAt: new Date()
    };

    const result = await users.insertOne(user);
    user._id = result.insertedId;

    req.logIn(user, (error) => {
      if (error) return next(error);

      res.status(201).json({
        user: publicUser(user)
      });
    });
  } catch (error) {
    if (error.code === 11000) {
      return res.status(409).json({
        error: "Este e-mail já possui uma conta no LifeFIT."
      });
    }

    next(error);
  }
});

app.post("/api/auth/login", loginLimiter, async (req, res, next) => {
  try {
    await connectDB();

    const user = await users.findOne({
      email: emailOf(req.body.email)
    });

    const validPassword =
      user &&
      user.passwordHash &&
      (await bcrypt.compare(
        String(req.body.password || ""),
        user.passwordHash
      ));

    if (!validPassword) {
      return res.status(401).json({
        error: "E-mail ou senha incorretos."
      });
    }

    req.logIn(user, (error) => {
      if (error) return next(error);

      res.json({
        user: publicUser(user)
      });
    });
  } catch (error) {
    next(error);
  }
});

app.get("/api/auth/me", (req, res) => {
  if (!req.user) {
    return res.status(401).json({
      error: "Não autenticado."
    });
  }

  res.json({
    user: publicUser(req.user)
  });
});

app.post("/api/auth/logout", (req, res, next) => {
  req.logout((error) => {
    if (error) return next(error);

    req.session.destroy(() => {
      res.clearCookie("lifefit.sid");
      res.status(204).end();
    });
  });
});

/* Mantém as rotas antigas de receitas, favoritos e dados públicos. */

function normalizarKey(key) {
  if (typeof key !== "string" || !key.trim() || key.length > 300) {
    const error = new Error("Chave inválida.");
    error.status = 400;
    throw error;
  }

  return key.trim();
}

function normalizarShared(value) {
  return value === true || value === "true";
}

function normalizarClientId(value) {
  if (
    typeof value !== "string" ||
    !/^[a-zA-Z0-9_-]{8,100}$/.test(value)
  ) {
    const error = new Error("Identificador do dispositivo inválido.");
    error.status = 400;
    throw error;
  }

  return value;
}

function storageFilter(key, shared, clientId) {
  return shared
    ? { key, shared: true, clientId: null }
    : { key, shared: false, clientId };
}

app.get("/api/storage/get", async (req, res) => {
  try {
    const key = normalizarKey(req.query.key);

    if (key.startsWith("usuario:") || key === "sessao:atual") {
      return res.status(403).json({
        error: "Dados privados não podem ser acessados por esta rota."
      });
    }

    const shared = normalizarShared(req.query.shared);
    const clientId = shared ? null : normalizarClientId(req.query.clientId);

    await connectDB();

    const doc = await storage.findOne(
      storageFilter(key, shared, clientId)
    );

    res.json(
      doc
        ? { key: doc.key, value: doc.value, shared: doc.shared }
        : null
    );
  } catch (error) {
    res.status(error.status || 500).json({
      error: error.message || "Erro ao consultar o banco."
    });
  }
});

app.post("/api/storage/set", async (req, res) => {
  try {
    const key = normalizarKey(req.body.key);

    if (key.startsWith("usuario:") || key === "sessao:atual") {
      return res.status(403).json({
        error: "Dados privados não podem ser gravados por esta rota."
      });
    }

    const shared = normalizarShared(req.body.shared);
    const clientId = shared ? null : normalizarClientId(req.body.clientId);

    const value =
      typeof req.body.value === "string"
        ? req.body.value
        : JSON.stringify(req.body.value ?? "");

    await connectDB();

    await storage.updateOne(
      storageFilter(key, shared, clientId),
      {
        $set: {
          key,
          value,
          shared,
          clientId,
          updatedAt: new Date()
        },
        $setOnInsert: {
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    res.json({ key, value, shared });
  } catch (error) {
    res.status(error.status || 500).json({
      error: error.message || "Erro ao salvar no banco."
    });
  }
});

app.post("/api/storage/delete", async (req, res) => {
  try {
    const key = normalizarKey(req.body.key);

    if (key.startsWith("usuario:") || key === "sessao:atual") {
      return res.status(403).json({
        error: "Dados privados não podem ser apagados por esta rota."
      });
    }

    const shared = normalizarShared(req.body.shared);
    const clientId = shared ? null : normalizarClientId(req.body.clientId);

    await connectDB();

    await storage.deleteOne(
      storageFilter(key, shared, clientId)
    );

    res.json({ key, deleted: true, shared });
  } catch (error) {
    res.status(error.status || 500).json({
      error: error.message || "Erro ao apagar no banco."
    });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    await connectDB();
    res.json({ ok: true, database: "mongodb", db: DB_NAME });
  } catch {
    res.status(500).json({
      ok: false,
      error: "Não foi possível conectar ao MongoDB."
    });
  }
});

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "LifeFIT Backend"
  });
});

app.use((error, req, res, next) => {
  console.error(error);

  res.status(500).json({
    error: "Não foi possível concluir esta ação. Tente novamente."
  });
});

connectDB()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`LifeFIT rodando na porta ${PORT}`);
    });
  })
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });

process.on("SIGTERM", async () => {
  if (client) await client.close();
  process.exit(0);
});