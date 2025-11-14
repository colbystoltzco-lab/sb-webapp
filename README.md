# StoltzCo SmartBuild Web App

Create SmartBuild jobs from a form and fetch outputs (e.g., purchase orders).
- Local: `python -m waitress --listen=127.0.0.1:8000 web_app:app`
- Env vars in `.env` (not committed). See "Environment" below.

## Environment
SMARTBUILD_BASE_URL=
SMARTBUILD_USERNAME=
SMARTBUILD_PASSWORD=
ADMIN_TOKEN=
FLASK_SECRET_KEY=change_me
# optional:
SMARTBUILD_TESTING_MODE=false
SMARTBUILD_TEMPLATE_ID=
PROJECTLIST_USER=
PROJECTLIST_DISTRIBUTOR=
PROJECTLIST_STATUS=All

## Health
GET /healthz → { ok: true/false }
