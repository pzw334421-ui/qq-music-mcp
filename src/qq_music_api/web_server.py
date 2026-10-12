
"""Authenticated HTTP entry point for remote QQ Music MCP."""
import os

import uvicorn

from .server import mcp


class AuthMiddleware:
    """Protect the public MCP endpoint with a bearer token."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")

        # Public health check for Render.
        if path == "/health":
            body = b'{"status":"ok"}'
            await send({
                "type": "http.response.start",
                "status": 200,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            })
            await send({
                "type": "http.response.body",
                "body": body,
            })
            return

        token = os.environ.get("MCP_AUTH_TOKEN", "")
        headers = dict(scope.get("headers", []))
        authorization = headers.get(b"authorization", b"").decode(
            "latin-1"
        )

        if not token:
            status, message = 503, b'{"error":"Server token not configured"}'
        elif authorization != f"Bearer {token}":
            status, message = 401, b'{"error":"Unauthorized"}'
        else:
            await self.app(scope, receive, send)
            return

        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(message)).encode()),
            ],
        })
        await send({
            "type": "http.response.body",
            "body": message,
        })


app = AuthMiddleware(mcp.streamable_http_app())


if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "10000")),
    )
