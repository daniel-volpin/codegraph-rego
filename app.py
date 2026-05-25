import logging
from codegraph.app import app as asgi_app
from codegraph.config import settings

logger = logging.getLogger("codegraph.app")
app = asgi_app


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting FastAPI app...")
    uvicorn.run("app:app", host=settings.backend_host, port=8000, reload=True)
