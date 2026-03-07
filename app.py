import logging
from codegraph.app import app

logger = logging.getLogger("codegraph.app")


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting FastAPI app...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
