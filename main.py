import time
import uuid
import os
import yaml
import jwt
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel
from typing import List
from dotenv import dotenv_values
from pathlib import Path

ALLOWED_ORIGIN = "https://dash-8brzdx.example.com"
GRADER_ORIGINS = {"https://sanand.workers.dev", "https://tds.s-anand.net"}
EMAIL = "22f3002768@ds.study.iitm.ac.in"

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-9kpu16qx.apps.exam.local"
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

app = FastAPI()


# Custom CORS + middleware headers
class StrictCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "")
        is_allowed_origin = origin == ALLOWED_ORIGIN
        is_grader_origin = origin in GRADER_ORIGINS

        if request.method == "OPTIONS":
            if is_allowed_origin:
                response = Response(status_code=200)
                response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "*"
            elif is_grader_origin:
                response = Response(status_code=200)
                response.headers["Access-Control-Allow-Origin"] = origin
                response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "*"
            else:
                response = Response(status_code=403)
            response.headers["X-Request-ID"] = str(uuid.uuid4())
            response.headers["X-Process-Time"] = "0.000001"
            return response

        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = time.perf_counter() - start_time

        response.headers["X-Request-ID"] = str(uuid.uuid4())
        response.headers["X-Process-Time"] = f"{process_time:.6f}"

        if is_allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"
        elif is_grader_origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"

        return response


app.add_middleware(StrictCORSMiddleware)


# ── Q1: /stats ──────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(values: str):
    nums = [int(v) for v in values.split(",") if v.strip()]
    count = len(nums)
    total = sum(nums)
    minimum = min(nums)
    maximum = max(nums)
    mean = total / count if count > 0 else 0.0
    return {
        "email": EMAIL,
        "count": count,
        "sum": total,
        "min": minimum,
        "max": maximum,
        "mean": round(mean, 10),
    }


# ── Q2: /verify ─────────────────────────────────────────────────────────────
class TokenRequest(BaseModel):
    token: str


@app.post("/verify")
async def verify_token(body: TokenRequest):
    try:
        payload = jwt.decode(
            body.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "sub", "email"]},
        )
        return JSONResponse(
            status_code=200,
            content={
                "valid": True,
                "email": payload.get("email"),
                "sub": payload.get("sub"),
                "aud": payload.get("aud"),
            },
        )
    except jwt.ExpiredSignatureError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Token expired"})
    except jwt.InvalidAudienceError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid audience"})
    except jwt.InvalidIssuerError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid issuer"})
    except jwt.InvalidSignatureError:
        return JSONResponse(status_code=401, content={"valid": False, "error": "Invalid signature"})
    except Exception as e:
        return JSONResponse(status_code=401, content={"valid": False, "error": str(e)})


# ── Q3: /effective-config ────────────────────────────────────────────────────
def coerce(key: str, value: str):
    """Apply type coercion rules."""
    if key in ("port", "workers"):
        return int(value)
    if key == "debug":
        return str(value).lower() in ("true", "1", "yes", "on")
    return str(value)


@app.get("/effective-config")
async def effective_config(request: Request):
    # Layer 1: hardcoded defaults
    config = {
        "port": 8000,
        "workers": 1,
        "debug": False,
        "log_level": "info",
        "api_key": "default-secret-000",
    }

    # Layer 2: config.development.yaml
    yaml_path = Path(__file__).parent / "config.development.yaml"
    if yaml_path.exists():
        with open(yaml_path) as f:
            yaml_data = yaml.safe_load(f) or {}
        for k, v in yaml_data.items():
            config[k] = coerce(k, str(v))

    # Layer 3: .env file (NUM_WORKERS → workers alias)
    env_path = Path(__file__).parent / ".env"
    if env_path.exists():
        env_vals = dotenv_values(env_path)
        mapping = {
            "APP_PORT": "port",
            "APP_DEBUG": "debug",
            "APP_LOG_LEVEL": "log_level",
            "APP_API_KEY": "api_key",
            "NUM_WORKERS": "workers",
        }
        for env_key, cfg_key in mapping.items():
            if env_key in env_vals:
                config[cfg_key] = coerce(cfg_key, env_vals[env_key])

    # Layer 4: OS environment variables with APP_* prefix
    os_mapping = {
        "APP_PORT": "port",
        "APP_WORKERS": "workers",
        "APP_DEBUG": "debug",
        "APP_LOG_LEVEL": "log_level",
        "APP_API_KEY": "api_key",
    }
    for env_key, cfg_key in os_mapping.items():
        val = os.environ.get(env_key)
        if val is not None:
            config[cfg_key] = coerce(cfg_key, val)

    # Layer 5: CLI overrides from ?set=key=value query params (highest precedence)
    set_params = request.query_params.getlist("set")
    for item in set_params:
        if "=" in item:
            k, v = item.split("=", 1)
            config[k] = coerce(k, v)

    # Mask api_key
    config["api_key"] = "****"

    return config
