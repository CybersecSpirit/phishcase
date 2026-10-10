from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from backend.investigation.http_security import SecurityMiddleware


def test_size_limit_precedes_dispatch_and_safe_response_headers():
    app = FastAPI()
    called = []

    @app.post("/api/example")
    async def echo(request: Request):
        called.append(True)
        return {"length": len(await request.body())}

    app.add_middleware(SecurityMiddleware)
    client = TestClient(app)
    response = client.post("/api/example", content=b"small")
    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Cache-Control"] == "no-store"
    assert len(response.headers["X-Request-ID"]) == 32
    called.clear()
    response = client.post(
        "/api/example", content=b"x", headers={"Content-Length": str(22 * 1024 * 1024)}
    )
    assert response.status_code == 413
    assert not called
