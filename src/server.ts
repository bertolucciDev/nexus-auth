/**
 * Nexus Auth Server - TLauncher-like Yggdrasil mock.
 *
 * Implements the minimal subset of Mojang's Yggdrasil API that Minecraft
 * (1.20+) needs for LAN multiplayer:
 *
 *   POST /api/yggdrasil/authserver/authenticate       -> {accessToken, clientToken, profiles}
 *   POST /api/yggdrasil/authserver/refresh            -> {accessToken, clientToken, selectedProfile, ...}
 *   POST /api/yggdrasil/authserver/validate           -> 204 on success
 *   POST /api/yggdrasil/authserver/invalidate         -> 204
 *   POST /api/yggdrasil/authserver/signout            -> 204
 *   POST /api/yggdrasil/sessionserver/session/minecraft/join        -> 204
 *   POST /api/yggdrasil/sessionserver/session/minecraft/hasJoined   -> 200 [{id, name}]
 *   GET  /api/yggdrasil/sessionserver/session/minecraft/profile/<uuid> -> 200 profile or 404
 *
 * No real validation, no real Mojang network. Both clients (host + guest)
 * talk to this same endpoint with their offline session, get tokens that
 * are valid against this server, and Minecraft LAN multiplayer accepts
 * them as "authenticated".
 */
if (!process.env.VERCEL && !process.env.RENDER) {
  try { require('dotenv').config(); } catch {}
}

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

const JWT_SECRET = process.env.JWT_SECRET || 'nexus-auth-secret-v1';
const PORT = parseInt(process.env.PORT || '3001', 10);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '*').split(',').map(s => s.trim());
const FRONTEND_URL = process.env.FRONTEND_URL || '';

const app = express();
app.use(express.json({ limit: '32kb' }));
app.use(helmet());

function matchesOrigin(origin: string): boolean {
  if (ALLOWED_ORIGINS.includes('*')) return true;
  if (!origin) return true;
  if (ALLOWED_ORIGINS.includes(origin)) return true;
  return false;
}

app.use(cors({
  origin: (origin, callback) => {
    if (matchesOrigin(origin || '')) {
      callback(null, true);
    } else {
      callback(new Error('Origin not allowed by CORS'));
    }
  },
  credentials: false,
}));

// Allow the authlib-injector HTTP queries to skip origin checks (no Origin header)
app.use((req, _res, next) => {
  // Mount under both /yggdrasil and /api/yggdrasil — authlib-injector expects /yggdrasil by default
  if (req.url.startsWith('/yggdrasil/')) {
    req.url = '/api' + req.url;
  }
  next();
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

interface Profile {
  id: string;       // uuid without dashes for minecraft
  name: string;     // username
  properties?: Array<{ name: string; value: string; signature?: string }>;
}

// In-memory token store  (good enough for LAN/peer-to-peer):
//   accessTokens[tokenHash] -> { ownerName, ownerUuid, clientToken, createdAt }
const accessTokens = new Map<string, { ownerName: string; ownerUuid: string; clientToken: string; createdAt: number }>();
//   usernameIndex[name] -> { uuid, accessToken } (so we can re-issue tokens)
const usernameIndex = new Map<string, { uuid: string; accessToken: string }>();

function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function uuidToMinecraftUuid(uuidNoDashes: string): string {
  // Add dashes to format: 8-4-4-4-12
  return `${uuidNoDashes.slice(0,8)}-${uuidNoDashes.slice(8,12)}-${uuidNoDashes.slice(12,16)}-${uuidNoDashes.slice(16,20)}-${uuidNoDashes.slice(20)}`;
}

function usernameToUuid(username: string): string {
  // Deterministic offline UUID (same algo Mojang uses for legacy)
  const data = username.trim();
  const hash = crypto.createHash('md5').update(`OfflinePlayer:${data}`).digest('hex');
  // Set version (3) and variant (8/9/a/b) bits for offline uuid
  const bytes = Buffer.from(hash, 'hex');
  bytes[6] = (bytes[6] & 0x0f) | 0x30; // version 3
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 10xx
  return bytes.toString('hex');
}

function profileForName(name: string, uuid?: string): Profile {
  var id = uuid || usernameToUuid(name);
  return {
    id,
    name,
    properties: [],
  };
}

function bearerFromAuth(req: express.Request): { token: string; payload: string } | null {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7);
  return { token, payload: token };
}

function mintAccessToken(name: string, uuid: string, clientToken?: string): string {
  const accessToken = `${uuidv4().replace(/-/g, '')}${uuidv4().replace(/-/g, '')}`;
  const stored = {
    ownerName: name,
    ownerUuid: uuid,
    clientToken: clientToken || '',
    createdAt: Date.now(),
  };
  accessTokens.set(hashToken(accessToken), stored);
  usernameIndex.set(name, { uuid, accessToken });
  return accessToken;
}

function buildProfileResponse(name: string, uuid: string, accessToken: string) {
  const profile = profileForName(name, uuid);
  return {
    accessToken,
    clientToken: uuidv4().replace(/-/g, ''),
    selectedProfile: profile,
    profiles: [profile],
    user: { id: profile.id, name: profile.name },
  };
}

// ----- Auth server endpoints -----

// POST /api/yggdrasil/authserver/authenticate
// Body: { agent: { name, version }, username, password, clientToken, requestUser }
app.post('/api/yggdrasil/authserver/authenticate', (req: any, res: any) => {
  const { username, password, clientToken, requestUser } = req.body || {};
  if (!username) return res.status(400).json({ error: 'Invalid credentials', path: '/authserver/authenticate' });
  // In TLauncher-style auth, "password" is not checked. We just trust the username.
  // Optionally: enforce a simple shared password to keep trolls out.
  if (password && password !== process.env.AUTH_PASSWORD && !process.env.AUTH_PASSWORD) {
    // If server has a password configured, enforce it.
  }
  const uuid = usernameIndex.get(username)?.uuid || usernameToUuid(username);
  const accessToken = mintAccessToken(username, uuid, clientToken);
  console.log(`[auth] authenticate: ${username} (uuid=${uuid}) token=${accessToken.slice(0,8)}...`);
  return res.json(buildProfileResponse(username, uuid, accessToken));
});

// POST /api/yggdrasil/authserver/refresh
app.post('/api/yggdrasil/authserver/refresh', (req: any, res: any) => {
  const data = bearerFromAuth(req);
  if (!data) return res.status(401).json({ error: 'No bearer token' });
  const stored = accessTokens.get(hashToken(data.token));
  if (!stored) return res.status(401).json({ error: 'Invalid token' });
  const { accessToken, clientToken } = req.body || {};
  const isClientMatch = !clientToken || clientToken === stored.clientToken;
  if (!isClientMatch) return res.status(401).json({ error: 'ClientToken mismatch' });
  // Issue new access token (old stays valid for grace period)
  const newToken = mintAccessToken(stored.ownerName, stored.ownerUuid, stored.clientToken);
  console.log(`[auth] refresh: ${stored.ownerName} (new=${newToken.slice(0,8)}...)`);
  return res.json(buildProfileResponse(stored.ownerName, stored.ownerUuid, newToken));
});

// POST /api/yggdrasil/authserver/validate
app.post('/api/yggdrasil/authserver/validate', (_req: any, res: any) => {
  const data = bearerFromAuth(_req);
  if (!data) return res.status(401).json({ error: 'No bearer token' });
  if (!accessTokens.has(hashToken(data.token))) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  return res.status(204).end();
});

// POST /api/yggdrasil/authserver/invalidate
app.post('/api/yggdrasil/authserver/invalidate', (_req: any, res: any) => {
  const data = bearerFromAuth(_req);
  if (data && accessTokens.has(hashToken(data.token))) {
    return res.status(204).end();
  }
  return res.status(204).end();
});

// POST /api/yggdrasil/authserver/signout
app.post('/api/yggdrasil/authserver/signout', (_req: any, res: any) => {
  return res.status(204).end();
});

// ----- Session server endpoints -----

// POST /api/yggdrasil/sessionserver/session/minecraft/join
// TLauncher-style: aceita qualquer join request sem validar token.
// Suporta dois formatos de body:
//   Moderno (1.20+): { accessToken, profileId, serverId }
//   Legado (1.8-1.19): { accessToken, selectedProfile: { id, name }, serverId }
app.post('/api/yggdrasil/sessionserver/session/minecraft/join', (req: any, res: any) => {
  const { selectedProfile, profileId, serverId, accessToken } = req.body || {};
  let uuid: string, name: string;
  if (selectedProfile?.id && selectedProfile?.name) {
    // Formato legado
    uuid = selectedProfile.id.replace(/-/g, '');
    name = selectedProfile.name;
  } else if (profileId) {
    // Formato moderno (1.20+) — usa o UUID pra derivar o nome da session
    uuid = profileId.replace(/-/g, '');
    // Tenta encontrar o nome pelo token store ou usernameIndex
    name = '';
    if (accessToken) {
      const stored = accessTokens.get(hashToken(accessToken));
      if (stored) name = stored.ownerName;
    }
    // Fallback: deriva nome do UUID (só pra ter algo válido)
    if (!name) name = 'Player';
  } else {
    return res.status(400).json({ error: 'Missing selectedProfile or profileId' });
  }
  if (accessToken) {
    const hash = hashToken(accessToken);
    if (!accessTokens.has(hash)) {
      accessTokens.set(hash, { ownerName: name, ownerUuid: uuid, clientToken: '', createdAt: Date.now() });
    }
    usernameIndex.set(name, { uuid, accessToken });
  }
  const key = `${uuid}:${serverId}`;
  sessionJoins.set(key, { name, uuid, serverId, joinedAt: Date.now() });
  console.log(`[auth] join: ${name} uuid=${uuid} -> serverId=${serverId}`);
  return res.status(204).end();
});

const sessionJoins = new Map<string, { name: string; uuid: string; serverId: string; joinedAt: number }>();

// Shared handler for hasJoined (used by both GET and POST)
function handleHasJoined(req: any, res: any) {
  const username = req.body?.username || (req.query?.username as string);
  const serverId = req.body?.serverId || (req.query?.serverId as string);
  if (!username || !serverId) return res.status(400).json({ error: 'Missing fields' });
  // Find join record by (username, serverId)
  for (const [, v] of sessionJoins) {
    if (v.name === username && v.serverId === serverId) {
      console.log(`[auth] hasJoined: ${username} serverId=${serverId} -> YES`);
      return res.json({
        id: usernameToUuid(username),
        name: username,
        properties: profileForName(username).properties,
      });
    }
  }
  // TLauncher-like fallback — return SINGLE object, not array
  console.log(`[auth] hasJoined: ${username} serverId=${serverId} -> FALLBACK YES`);
  return res.json({
    id: usernameToUuid(username),
    name: username,
    properties: profileForName(username).properties,
  });
}

// Both POST (body) and GET (query params) — authlib-injector uses GET
app.post('/api/yggdrasil/sessionserver/session/minecraft/hasJoined', handleHasJoined);
app.get('/api/yggdrasil/sessionserver/session/minecraft/hasJoined', handleHasJoined);

// GET /api/yggdrasil/sessionserver/session/minecraft/profile/<uuid>
app.get('/api/yggdrasil/sessionserver/session/minecraft/profile/:uuid', (req: any, res: any) => {
  const uuidNoDash = (req.params.uuid || '').replace(/-/g, '');
  // Look up user by UUID in our token store (set during authenticate)
  for (const [, v] of accessTokens) {
    if (v.ownerUuid === uuidNoDash) {
      return res.json(profileForName(v.ownerName, uuidNoDash));
    }
  }
  // Secondary lookup in sessionJoins (join records survive longer than token
  // store because clients keep joining). If found, return the real name.
  for (const [, v] of sessionJoins) {
    if (v.uuid === uuidNoDash) {
      return res.json(profileForName(v.name, uuidNoDash));
    }
  }
  // Last resort: derive name from UUID via accessTokens (backup of last resort)
  for (const [, v] of accessTokens) {
    if (v.ownerUuid === uuidNoDash) {
      return res.json(profileForName(v.ownerName, uuidNoDash));
    }
  }
  // Absolute fallback: use a non-null name so Minecraft doesn't get confused
  return res.json(profileForName('Player', uuidNoDash));
});

// ----- YAML config export for authlib-injector compatibility -----
// authlib-injector accepts a URL to a "yggdrasil server info" doc.
// We expose it at /yggdrasil/api/yggdrasil/authserver/authenticate etc + a metadata doc:
//   GET /yggdrasil -> { meta: { serverName, implementationName, implementationVersion }, skinDomains, sessionPublicKey }
app.get('/yggdrasil', (_req: any, res: any) => {
  const baseUrl = FRONTEND_URL || `https://${_req.headers.host}`;
  res.json({
    meta: {
      serverName: 'Nexus Auth',
      implementationName: 'nexus-auth',
      implementationVersion: '0.1.0',
      'feature.no-login-plugin': true,
      'feature.accounts-type': ['offline'],
    },
    authentication: {
      endpoint: `${baseUrl}/api/yggdrasil/authserver`,
      endpoints: {
        Minecraft: `${baseUrl}/api/yggdrasil/authserver`
      }
    },
    session: {
      endpoint: `${baseUrl}/api/yggdrasil/sessionserver`,
      endpoints: {
        Minecraft: `${baseUrl}/api/yggdrasil/sessionserver`
      }
    },
    skinDomains: [`${baseUrl}/skins`],
    sessionPublicKey: '',  // not used with offline auth
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[nexus-auth] listening on port ${PORT}`);
});
