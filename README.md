# SSO OIDC Service

OIDC 认证服务，用于对接 Outline Wiki。

## 安装

```
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## 配置

复制 .env.example 为 .env，按需修改配置。

## 运行

```
uvicorn app:app --reload
```

默认监听 http://127.0.0.1:8000

## 端点

- GET /.well-known/openid-configuration — OIDC 发现
- GET/POST /authorize — 授权端点
- POST /token — Token 端点
- GET /userinfo — 用户信息端点
- GET /health — 健康检查
- GET /docs — OpenAPI 文档

## 默认账号

```
用户名：admin
密码：admin123
```

（通过 .env 的 SSO_SEED_* 配置，仅首次启动时创建）
