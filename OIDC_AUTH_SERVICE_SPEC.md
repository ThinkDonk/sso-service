# Outline OIDC 认证服务对接文档

## 一、背景

Outline 内置了 OIDC 插件，支持对接任何符合 OpenID Connect 标准的第三方认证服务。当你在 Outline 的环境变量中配置好 OIDC 参数后，登录页会出现一个 "OpenID Connect" 按钮（显示名称可自定义），用户点击后跳转到你的认证服务完成登录，再跳回 Outline，由 Outline 根据返回的用户信息创建或关联账号。

本文档说明你的认证服务需要实现哪些内容，以及 Outline 期望的数据格式。

---

## 二、Outline 支持两种配置方式

### 方式一：手动指定端点（Manual）

直接在环境变量中写明各个端点地址：

| 变量 | 必需 | 说明 |
|---|---|---|
| `OIDC_CLIENT_ID` | 是 | 你的服务分配的 client_id |
| `OIDC_CLIENT_SECRET` | 是 | 你的服务分配的 client_secret |
| `OIDC_AUTH_URI` | 是 | 授权端点完整 URL |
| `OIDC_TOKEN_URI` | 是 | Token 端点完整 URL |
| `OIDC_USERINFO_URI` | 是 | 用户信息端点完整 URL |
| `OIDC_LOGOUT_URI` | 否 | 登出端点 URL（设置后 Outline 注销时会跳转到此地址） |
| `OIDC_DISPLAY_NAME` | 否 | 按钮显示名称，默认 `OpenID Connect` |
| `OIDC_SCOPES` | 否 | 请求的 scope，默认 `openid profile email` |
| `OIDC_USERNAME_CLAIM` | 否 | 用户名字段名，默认 `preferred_username` |
| `OIDC_DISABLE_REDIRECT` | 否 | 禁止自动跳转 OIDC 登录页 |

### 方式二：自动发现（Issuer Discovery）

只需设置 `OIDC_CLIENT_ID`、`OIDC_CLIENT_SECRET` 和 `OIDC_ISSUER_URL`，Outline 启动时会自动请求 `{ISSUER_URL}/.well-known/openid-configuration` 来获取所有端点地址。如果你的服务实现了 well-known discovery，推荐使用此方式。

---

## 三、需要实现的端点

### 3.1 授权端点（Authorization Endpoint）

- **路径**：自定义，通过 `OIDC_AUTH_URI` 或 well-known 中的 `authorization_endpoint` 指定
- **方法**：`GET`
- **职责**：接收 Outline 发来的授权请求，向用户展示登录页面，用户登录后 redirect 回 Outline

**请求参数：**

| 参数 | 说明 |
|---|---|
| `response_type=code` | 固定值 |
| `client_id` | 你分配给 Outline 的 client_id |
| `redirect_uri` | Outline 的 callback 地址，格式为 `{OUTLINE_URL}/auth/oidc.callback` |
| `scope` | 默认为 `openid profile email`（空格分隔） |
| `state` | Outline 生成的随机字符串，回调时必须原样返回。包含 CSRF 防护信息 |
| `code_challenge` | [可选] 如果启用了 PKCE（S256），会带上此参数 |
| `code_challenge_method` | [可选] 值为 `S256` |

**你的服务需要做的：**
1. 校验 `redirect_uri` 与你预注册的一致
2. 完成用户认证
3. 生成一次性 `code`（建议有效期 10 分钟）
4. 将用户重定向到 `redirect_uri`，附带 `?code=xxx&state=xxx`（state 必须原样返回）

---

### 3.2 Token 端点（Token Endpoint）

- **路径**：自定义，通过 `OIDC_TOKEN_URI` 或 well-known 中的 `token_endpoint` 指定
- **方法**：`POST`
- **Content-Type**：`application/x-www-form-urlencoded`
- **职责**：用授权码换取 token

**请求参数：**

| 参数 | 说明 |
|---|---|
| `grant_type=authorization_code` | 固定值 |
| `code` | 授权端点返回的 code |
| `redirect_uri` | 与授权请求中相同的回调地址 |
| `client_id` | client_id |
| `client_secret` | client_secret |
| `code_verifier` | [可选] PKCE 的 code_verifier |

**你的服务需要返回的 JSON：**

```json
{
  "access_token": "xxx",
  "token_type": "Bearer",
  "expires_in": 3600,
  "id_token": "eyJhbGciOi...",
  "refresh_token": "yyy"
}
```

**字段说明：**

| 字段 | 必需 | 说明 |
|---|---|---|
| `access_token` | 是 | 用于后续请求 userinfo 的 Bearer token |
| `token_type` | 是 | 固定 `Bearer` |
| `expires_in` | 是 | access_token 有效期，单位秒 |
| `id_token` | 是 | JWT 格式的身份令牌，详见下方说明 |
| `refresh_token` | 否 | 用于刷新 token。不提供则 Outline 无法刷新登录态 |

**id_token 的 JWT payload 至少包含：**

```json
{
  "iss": "你的认证服务地址",
  "sub": "用户的唯一标识",
  "aud": "client_id",
  "exp": 1234567890,
  "iat": 1234567890,
  "email": "user@example.com"
}
```

注意：Outline **不验签** id_token（仅做 JWT decode），所以 token 端点返回的 `sub` 和 `email` 仅作为 userinfo 返回不完整时的**兜底数据**。

---

### 3.3 用户信息端点（Userinfo Endpoint）

- **路径**：自定义，通过 `OIDC_USERINFO_URI` 或 well-known 中的 `userinfo_endpoint` 指定
- **方法**：`GET` 或 `POST`（Outline 默认用 GET）
- **认证**：`Authorization: Bearer {access_token}`
- **职责**：返回当前用户的信息，这是 Outline 获取用户资料的主要来源

**你的服务需要返回的 JSON：**

```json
{
  "sub": "user-unique-identifier",
  "email": "user@example.com",
  "email_verified": true,
  "preferred_username": "john",
  "name": "John Doe",
  "picture": "https://example.com/avatars/john.png"
}
```

**字段详细说明：**

| 字段 | 必需 | 说明 |
|---|---|---|
| `sub` | **是** | 用户的唯一标识符。Outline 用它作为 `profileId` 来关联用户。如果 userinfo 中缺少此字段，Outline 会尝试从 id_token 的 `sub` 中 fallback。两者都没有则认证失败 |
| `email` | **是** | 用户的邮箱地址。Outline **强制要求**。如果 userinfo 中缺少，会尝试从 id_token 的 `email` 中 fallback。都没有则认证失败并报错 |
| `email_verified` | 否 | 邮箱是否已验证。可以是布尔值 `true`/`false` 或字符串 `"true"`/`"false"`。Outline 会统一转为布尔值。如果不存在则为 `undefined` |
| `preferred_username` | 否 | 用户名。默认被用作 Outline 中的显示名称。可通过 `OIDC_USERNAME_CLAIM` 环境变量修改要读取的字段名 |
| `name` | **是** | 用户全名。如果 `preferred_username` 或自定义的 username claim 取不到值，会 fallback 到 `name`。都取不到则认证失败 |
| `username` | 否 | 第三个 fallback 用户名来源 |
| `picture` | 否 | 头像 URL。**必须是 https/http URL**。如果是 base64 data URL（以 `data:` 开头），Outline 会**主动过滤掉**，不会存入数据库 |

**字段优先级总结：**

```
用户名获取顺序：OIDC_USERNAME_CLAIM 指定的字段 > preferred_username > name > username
用户 ID 获取顺序：userinfo.sub > id_token.sub > userinfo.id
邮箱获取顺序：   userinfo.email > id_token.email
```

---

### 3.4 Well-Known Discovery 端点（推荐实现）

- **路径**：`/.well-known/openid-configuration`
- **方法**：`GET`
- **职责**：返回服务元数据，让 Outline 自动发现端点地址

**返回的 JSON：**

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "end_session_endpoint": "https://auth.example.com/logout",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "scopes_supported": ["openid", "profile", "email"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"]
}
```

**Outline 的使用逻辑：**

- `authorization_endpoint`、`token_endpoint`、`userinfo_endpoint` — **必须存在**，否则启动失败
- `end_session_endpoint` — 如果存在，自动作为登出地址
- `code_challenge_methods_supported` — 如果包含 `"S256"`，自动启用 PKCE
- `issuer`、`scopes_supported` 等仅用于日志记录

---

### 3.5 登出端点（可选）

- **路径**：自定义，通过 `OIDC_LOGOUT_URI` 或 well-known 的 `end_session_endpoint` 指定
- **职责**：用户从 Outline 注销后，Outline 会将浏览器重定向到此地址

Outline 的行为：当用户主动登出时，Outline 清除本地 session 后执行 `window.location.href = OIDC_LOGOUT_URI`，不做任何参数传递。

---

### 3.6 Token 刷新端点（可选但建议实现）

- **路径**：与 Token 端点相同
- **方法**：`POST`
- **Content-Type**：`application/x-www-form-urlencoded`
- **请求参数**：
  - `grant_type=refresh_token`
  - `refresh_token=xxx`
  - `client_id=xxx`
  - `client_secret=xxx`

**返回格式与 token 端点一致：**

```json
{
  "access_token": "new_access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "new_refresh_token"
}
```

不实现此端点则 Outline 的 token 过期后用户需要重新登录。

---

## 四、完整认证时序

```
Outline (Browser)              Outline (Server)             你的认证服务
     |                              |                            |
     |  1. 用户点"登录"               |                            |
     |------ GET /auth/oidc ------->|                            |
     |                              |  2. 生成 state(含CSRF)      |
     |                              |  3. 302 Redirect ---------->|
     |                              |     /authorize?             |
     |                              |     client_id=xxx           |
     |                              |     redirect_uri=...        |
     |                              |     scope=openid...         |
     |                              |     state=xxx               |
     |                              |                            |
     |  4. 跟随重定向                |                            |
     |----------------------------- 你的服务 /authorize --------->|
     |                              |                            |
     |                              |              5. 用户登录认证 |
     |                              |                            |
     |  6. 302 Redirect             |                            |
     |     回调地址?code=xxx&state=xxx                            |
     |<---------------------------------------------------------|
     |                              |                            |
     |  7. GET /auth/oidc.callback  |                            |
     |      ?code=xxx&state=xxx     |                            |
     |----------------------------->|                            |
     |                              |  8. POST /token ---------->|
     |                              |     code=xxx               |
     |                              |     client_secret=xxx      |
     |                              |                            |
     |                              |  9. 返回 access_token      |
     |                              |     id_token、refresh_token |
     |                              |<---------------------------|
     |                              |                            |
     |                              | 10. GET /userinfo -------->|
     |                              |     Bearer {access_token}  |
     |                              |                            |
     |                              | 11. 返回用户 JSON          |
     |                              |     sub/email/name...      |
     |                              |<---------------------------|
     |                              |                            |
     |                              | 12. 创建/关联账号           |
     |                              |                            |
     |  13. 302 到应用首页           |                            |
     |<-----------------------------|                            |
```

---

## 五、关键注意事项

1. **Callback URL 是固定的**：`{OUTLINE_URL}/auth/oidc.callback`（如 `https://wiki.example.com/auth/oidc.callback`），你需要在你的认证服务中预先注册这个回调地址
2. **email 是强制字段**：userinfo 或 id_token 中必须包含有效 email，否则认证直接失败
3. **sub 是强制字段**：用于唯一标识用户，Outline 用它做账号关联，用户信息变更不影响关联
4. **state 必须原样返回**：Outline 使用它做 CSRF 防护和跨域状态传递，篡改会导致认证失败
5. **头像不要用 base64**：如果 picture 字段是 `data:image/...` 格式的 base64 URL，Outline 会丢弃它
6. **PKCE 可选**：在 well-known 中声明 `code_challenge_methods_supported: ["S256"]` 即可启用，手动配置模式下永远不启用 PKCE
7. **access_token 用 Bearer 方式传递**：Outline 请求你的 userinfo 端点时，Header 格式为 `Authorization: Bearer {access_token}`
8. **Scope 是可配置的**：Outline 默认请求 `openid profile email`，但管理员可以通过 `OIDC_SCOPES` 环境变量修改
