import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import bcrypt from 'bcryptjs';
import { Client, Databases, Users, ID, Query } from 'node-appwrite';

const app = express();

const {
  PORT = 3000,
  DEV_MODE = 'true',

  APPWRITE_ENDPOINT,
  APPWRITE_PROJECT_ID,
  APPWRITE_API_KEY,

  APPWRITE_DB_ID,
  APPWRITE_LOGIN_CODES_COLLECTION_ID,   // login_codes
  APPWRITE_USER_PROFILES_COLLECTION_ID  // user_profiles
} = process.env;

app.use(cors({ origin: ['*'] }));
app.use(express.json());
app.use(morgan(DEV_MODE === 'true' ? 'dev' : 'combined'));

const sixDigit = () => Math.floor(100000 + Math.random() * 900000).toString();
const dlog = (...a) => DEV_MODE === 'true' && console.log('[DEV]', ...a);

function newAppwrite() {
  const client = new Client()
    .setEndpoint(APPWRITE_ENDPOINT)
    .setProject(APPWRITE_PROJECT_ID)
    .setKey(APPWRITE_API_KEY);
  return { client, db: new Databases(client), users: new Users(client) };
}

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/debug/env', (_req, res) => res.json({
  endpoint: !!APPWRITE_ENDPOINT,
  project: !!APPWRITE_PROJECT_ID,
  apiKey: !!APPWRITE_API_KEY,
  db: APPWRITE_DB_ID,
  collCodes: APPWRITE_LOGIN_CODES_COLLECTION_ID,
  collProfiles: APPWRITE_USER_PROFILES_COLLECTION_ID
}));

// ---------- Enviar código ----------
app.post('/auth/send-code', async (req, res) => {
  try {
    const url = new URL(req.originalUrl, 'http://localhost');
    const role = String(url.searchParams.get('role') || 'cliente').trim();
    const ref  = url.searchParams.get('ref') ? String(url.searchParams.get('ref')).trim() : null;

    const email = (req.body?.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ ok: false, error: 'E-mail é obrigatório' });

    const { db, users } = newAppwrite();

    // garante usuário Appwrite
    let userId = null;
    try {
      const listed = await users.list({ queries: [Query.equal('email', email)] });
      if (listed.total > 0) userId = listed.users[0].$id;
    } catch {}
    if (!userId) userId = (await users.create(ID.unique(), email)).$id;

    // gera + grava código
    const code = sixDigit();
    const code_hash = await bcrypt.hash(code, 10);
    const expires_at = Date.now() + 10 * 60 * 1000;

    // limpa antigos
    try {
      const old = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_LOGIN_CODES_COLLECTION_ID, [Query.equal('email', email)]);
      await Promise.all((old.documents || []).map(d => db.deleteDocument(APPWRITE_DB_ID, APPWRITE_LOGIN_CODES_COLLECTION_ID, d.$id)));
    } catch {}

    await db.createDocument(APPWRITE_DB_ID, APPWRITE_LOGIN_CODES_COLLECTION_ID, ID.unique(), {
      email, code_hash, role, ref, expires_at
    });

    if (DEV_MODE === 'true') {
      return res.json({ ok: true, message: 'Código gerado (DEV)', code_dev: code, expires_at });
    }
    // Produção: integrar envio real (Appwrite Messaging/SMTP)
    return res.json({ ok: true, message: 'Código enviado' });

  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

// ---------- Verificar código ----------
app.post('/auth/verify-code', async (req, res) => {
  try {
    const email = (req.body?.email || '').trim().toLowerCase();
    const code  = (req.body?.code || '').trim();
    const role  = String(req.body?.role || 'cliente').trim();
    const ref   = req.body?.ref ? String(req.body.ref).trim() : null;

    if (!email || !code) return res.status(400).json({ ok: false, error: 'E-mail e código são obrigatórios' });

    const { db, users } = newAppwrite();

    // pega último código
    const list = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_LOGIN_CODES_COLLECTION_ID, [
      Query.equal('email', email),
      Query.orderDesc('$createdAt'),
      Query.limit(1)
    ]);
    const doc = list.documents?.[0];
    if (!doc) return res.status(400).json({ ok: false, error: 'Nenhum código encontrado' });
    if (Date.now() > Number(doc.expires_at)) return res.status(400).json({ ok: false, error: 'Código expirado' });

    // compara
    const ok = await bcrypt.compare(code, doc.code_hash);
    if (!ok) return res.status(400).json({ ok: false, error: 'Código inválido' });

    // garante user
    let userId = null;
    try {
      const listed = await users.list({ queries: [Query.equal('email', email)] });
      if (listed.total > 0) userId = listed.users[0].$id;
    } catch {}
    if (!userId) return res.status(400).json({ ok: false, error: 'Usuário não encontrado — gere o código novamente' });

    // roles como STRING JSON (compatível com seu Appwrite)
    const roles = { cliente:false, transportador:false, afiliado:false, admin:false };
    if (['cliente','transportador','afiliado'].includes(role)) roles[role] = true;
    const rolesStr = JSON.stringify(roles);

    // cria/atualiza profile
    const profs = await db.listDocuments(APPWRITE_DB_ID, APPWRITE_USER_PROFILES_COLLECTION_ID, [Query.equal('user_id', userId)]);
    if (profs.total > 0) {
      await db.updateDocument(APPWRITE_DB_ID, APPWRITE_USER_PROFILES_COLLECTION_ID, profs.documents[0].$id, {
        email, roles: rolesStr, ...(ref ? {ref} : {})
      });
    } else {
      await db.createDocument(APPWRITE_DB_ID, APPWRITE_USER_PROFILES_COLLECTION_ID, ID.unique(), {
        user_id: userId, email, roles: rolesStr, ...(ref ? {ref} : {})
      });
    }

    // invalida o código usado
    try { await db.deleteDocument(APPWRITE_DB_ID, APPWRITE_LOGIN_CODES_COLLECTION_ID, doc.$id); } catch {}

    const token_demo = `ok-${userId}-${Date.now()}`;
    return res.json({ ok: true, user_id: userId, role_set: role, token: token_demo });

  } catch (err) {
    return res.status(500).json({ ok: false, error: String(err?.message || err) });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('[OK] Auth 6 dígitos rodando'));
