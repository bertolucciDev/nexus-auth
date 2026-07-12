# Nexus Auth

Mock Yggdrasil auth server used by **Nexus Launcher** for LAN multiplayer in Minecraft 1.20+ without requiring a Microsoft account.

This is the same approach **TLauncher** uses:

1. The launcher downloads `authlib-injector.jar` from Maven Central once.
2. The launcher appends `-javaagent:authlib-injector.jar=yggdrasil_url=https://nexus-auth-uv6x.onrender.com` to the JVM args.
3. Minecraft sends its auth calls to our endpoints instead of Mojang.
4. We accept any username (deterministic offline UUID) and issue token pairs.
5. Both host and guest use the same auth server, so Mojang Yggdrasil-style validation succeeds.

## Endpoints

- `POST /api/yggdrasil/authserver/authenticate`
- `POST /api/yggdrasil/authserver/refresh`
- `POST /api/yggdrasil/authserver/validate`
- `POST /api/yggdrasil/authserver/invalidate`
- `POST /api/yggdrasil/authserver/signout`
- `POST /api/yggdrasil/sessionserver/session/minecraft/join`
- `POST /api/yggdrasil/sessionserver/session/minecraft/hasJoined`
- `GET  /api/yggdrasil/sessionserver/session/minecraft/profile/<uuid>`

Equivalent in-memory store of tokens, deterministic UUID via `OfflinePlayer:<name>` MD5 hash.

## Deploy on Render

The repo is ready for `render.yaml`. Set `JWT_SECRET` on the Render dashboard to a random string.

Production URL: https://nexus-auth-uv6x.onrender.com
