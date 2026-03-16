"""
FastAPI application for K8sGuard — Kubernetes Security Scanner.

Endpoints:
    - POST /reset: Reset the scan environment
    - POST /step: Execute a scan action
    - GET /state: Get current scan state
    - GET /schema: Get action/observation schemas
    - GET /healthz: Health check

Usage:
    uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
"""

try:
    from openenv.core.env_server.http_server import create_app
    from ..models import K8sGuardAction, K8sGuardObservation
    from .k8sguard_environment import K8sGuardEnvironment
except ImportError:
    from openenv.core.env_server.http_server import create_app
    from models import K8sGuardAction, K8sGuardObservation
    from server.k8sguard_environment import K8sGuardEnvironment

import logging

logger = logging.getLogger(__name__)

app = create_app(
    K8sGuardEnvironment,
    K8sGuardAction,
    K8sGuardObservation,
    env_name="k8sguard",
    max_concurrent_envs=1,
)


@app.get("/healthz")
async def healthz():
    """Health check — tests if environment can connect to K8s."""
    try:
        env = K8sGuardEnvironment()
        health = env.backend.check_health()
        return {"status": "ok", "cluster_health": health}
    except Exception as e:
        logger.error(f"Health check failed: {e}", exc_info=True)
        return {"status": "error", "error": str(e)}


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for `uv run server` and direct execution."""
    import argparse
    import os
    import uvicorn

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    import warnings
    warnings.filterwarnings("ignore", category=DeprecationWarning)

    parser = argparse.ArgumentParser(description="K8sGuard server")
    parser.add_argument("--port", type=int, default=port)
    parser.add_argument("--host", default=host)
    parser.add_argument("--scan-mode", choices=("scan", "training"), default=None,
                        help="Override SCAN_MODE env var")
    parser.add_argument("--llm-backend", choices=("openai", "hf", "anthropic"), default=None,
                        help="Override LLM_BACKEND env var")
    parser.add_argument("--llm-model", default=None,
                        help="Override LLM_MODEL env var")
    parser.add_argument("--anthropic-api-key", default=None,
                        help="Anthropic API key (overrides ANTHROPIC_API_KEY env var)")
    args = parser.parse_args()

    if args.scan_mode:
        os.environ["SCAN_MODE"] = args.scan_mode
    if args.llm_backend:
        os.environ["LLM_BACKEND"] = args.llm_backend
    if args.llm_model:
        os.environ["LLM_MODEL"] = args.llm_model
    if args.anthropic_api_key:
        os.environ["ANTHROPIC_API_KEY"] = args.anthropic_api_key

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
