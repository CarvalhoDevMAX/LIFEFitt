const express = require("express");
const path = require("path");
const { MongoClient } = require("mongodb");

const app = express();

// =========================================================
// CORS
// =========================================================

const FRONTEND_ORIGINS = [
  "https://carvalhodevmax.github.io",
  "http://127.0.0.1:3000",
  "http://localhost:3000",
  "http://127.0.0.1:5500",
  "http://localhost:5500"
];

app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (FRONTEND_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }

  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET,POST,DELETE,OPTIONS"
  );

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

const PORT = process.env.PORT || 10000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || "lifefit";

if (!MONGODB_URI) {
  console.error("ERRO: a variável MONGODB_URI não foi configurada.");
  process.exit(1);
}

app.use(express.json({ limit: "1mb" }));

// Permite acessar o index.html e outros arquivos do projeto
app.use(express.static(path.join(__dirname)));

let client;
let collection;

async function connectDB() {
  if (collection) return collection;

  client = new MongoClient(MONGODB_URI);

  await client.connect();

  const db = client.db(DB_NAME);

  collection = db.collection("storage");

  await collection.createIndex(
    { key: 1, shared: 1, clientId: 1 },
    { unique: true }
  );

  console.log(
    `MongoDB conectado: banco "${DB_NAME}", coleção "storage"`
  );

  return collection;
}

// =========================================================
// VALIDAÇÕES
// =========================================================

function normalizarKey(key) {
  if (typeof key !== "string" || !key.trim()) {
    const error = new Error("A chave é obrigatória.");
    error.status = 400;
    throw error;
  }

  if (key.length > 300) {
    const error = new Error("A chave é muito longa.");
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
    const error = new Error(
      "Identificador do dispositivo inválido."
    );

    error.status = 400;

    throw error;
  }

  return value;
}

function filtroDocumento(key, shared, clientId) {
  if (shared) {
    return {
      key,
      shared: true,
      clientId: null
    };
  }

  return {
    key,
    shared: false,
    clientId
  };
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// =========================================================
// TESTE DO SERVIDOR / MONGODB
// =========================================================

app.get("/api/health", async (req, res) => {
  try {
    await connectDB();

    res.json({
      ok: true,
      database: "mongodb",
      db: DB_NAME,
      collection: "storage"
    });
  } catch (error) {
    console.error("Health check:", error);

    res.status(500).json({
      ok: false,
      error: "Não foi possível conectar ao MongoDB."
    });
  }
});

// =========================================================
// GET
// =========================================================

app.get("/api/storage/get", async (req, res) => {
  try {
    const key = normalizarKey(req.query.key);

    const shared = normalizarShared(
      req.query.shared
    );

    const clientId = shared
      ? null
      : normalizarClientId(req.query.clientId);

    const col = await connectDB();

    const doc = await col.findOne(
      filtroDocumento(key, shared, clientId)
    );

    if (!doc) {
      return res.status(200).json(null);
    }

    res.json({
      key: doc.key,
      value: doc.value,
      shared: doc.shared
    });
  } catch (error) {
    console.error("GET storage:", error);

    res.status(error.status || 500).json({
      error: error.status
        ? error.message
        : "Erro ao consultar o banco."
    });
  }
});

// =========================================================
// SET
// =========================================================

app.post("/api/storage/set", async (req, res) => {
  try {
    const key = normalizarKey(req.body.key);

    const shared = normalizarShared(
      req.body.shared
    );

    const clientId = shared
      ? null
      : normalizarClientId(req.body.clientId);

    const value =
      typeof req.body.value === "string"
        ? req.body.value
        : JSON.stringify(req.body.value ?? "");

    const col = await connectDB();

    const doc = {
      key,
      value,
      shared,
      clientId,
      updatedAt: new Date()
    };

    await col.updateOne(
      filtroDocumento(key, shared, clientId),
      {
        $set: doc,
        $setOnInsert: {
          createdAt: new Date()
        }
      },
      {
        upsert: true
      }
    );

    res.json({
      key,
      value,
      shared
    });
  } catch (error) {
    console.error("SET storage:", error);

    res.status(error.status || 500).json({
      error: error.status
        ? error.message
        : "Erro ao salvar no banco."
    });
  }
});

// =========================================================
// DELETE
// =========================================================

app.post("/api/storage/delete", async (req, res) => {
  try {
    const key = normalizarKey(req.body.key);

    const shared = normalizarShared(
      req.body.shared
    );

    const clientId = shared
      ? null
      : normalizarClientId(req.body.clientId);

    const col = await connectDB();

    await col.deleteOne(
      filtroDocumento(key, shared, clientId)
    );

    res.json({
      key,
      deleted: true,
      shared
    });
  } catch (error) {
    console.error("DELETE storage:", error);

    res.status(error.status || 500).json({
      error: error.status
        ? error.message
        : "Erro ao excluir do banco."
    });
  }
});

// =========================================================
// LIST
// =========================================================

app.get("/api/storage/list", async (req, res) => {
  try {
    const prefix =
      typeof req.query.prefix === "string"
        ? req.query.prefix
        : "";

    const shared = normalizarShared(
      req.query.shared
    );

    const clientId = shared
      ? null
      : normalizarClientId(req.query.clientId);

    if (prefix.length > 300) {
      return res.status(400).json({
        error: "O prefixo é muito longo."
      });
    }

    const col = await connectDB();

    const filtro = shared
      ? {
          shared: true,
          clientId: null,
          key: {
            $regex: "^" + escapeRegex(prefix)
          }
        }
      : {
          shared: false,
          clientId,
          key: {
            $regex: "^" + escapeRegex(prefix)
          }
        };

    const docs = await col
      .find(
        filtro,
        {
          projection: {
            _id: 0,
            key: 1
          }
        }
      )
      .sort({
        key: 1
      })
      .toArray();

    res.json({
      keys: docs.map(doc => doc.key),
      prefix,
      shared
    });
  } catch (error) {
    console.error("LIST storage:", error);

    res.status(500).json({
      error: "Erro ao listar dados."
    });
  }
});

// =========================================================
// PÁGINA PRINCIPAL
// =========================================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "index.html")
  );
});

// =========================================================
// ERROS
// =========================================================

app.use((err, req, res, next) => {
  console.error(err);

  res.status(500).json({
    error: "Erro interno do servidor."
  });
});

// =========================================================
// INICIAR SERVIDOR
// =========================================================

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `LifeFit rodando na porta ${PORT}`
    );
  }
);

// =========================================================
// ENCERRAMENTO
// =========================================================

process.on("SIGINT", async () => {
  if (client) {
    await client.close();
  }

  process.exit(0);
});

process.on("SIGTERM", async () => {
  if (client) {
    await client.close();
  }

  process.exit(0);
});