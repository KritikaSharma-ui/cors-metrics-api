import time
import uuid
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

ALLOWED_ORIGIN = "https://dash-8brzdx.example.com"
EMAIL = "22f3002768@ds.study.iitm.ac.in"

app = FastAPI()

# Custom CORS middleware to handle strict per-origin policy
class StrictCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get("origin", "")
        is_allowed_origin = origin == ALLOWED_ORIGIN

        # Handle preflight OPTIONS requests
        if request.method == "OPTIONS":
            if is_allowed_origin:
                response = Response(status_code=200)
                response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
                response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "*"
                response.headers["Access-Control-Allow-Credentials"] = "true"
                response.headers["X-Request-ID"] = str(uuid.uuid4())
                response.headers["X-Process-Time"] = "0.000001"
                return response
            else:
                # Reject preflight from unauthorized origin - no ACAO header
                response = Response(status_code=403)
                response.headers["X-Request-ID"] = str(uuid.uuid4())
                response.headers["X-Process-Time"] = "0.000001"
                return response

        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = time.perf_counter() - start_time

        # Add mandatory middleware headers to every response
        response.headers["X-Request-ID"] = str(uuid.uuid4())
        response.headers["X-Process-Time"] = f"{process_time:.6f}"

        # Add ACAO header only for allowed origin
        if is_allowed_origin:
            response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN
            response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "*"

        return response


app.add_middleware(StrictCORSMiddleware)


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
