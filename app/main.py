"""
This module configures the BlackSheep application before it starts.
"""

from blacksheep import Application
from blacksheep.server.diagnostics import get_diagnostic_app
from blacksheep.server.redirects import get_trailing_slash_middleware
from dbsession import AsyncSessionLocal
from rodi import Container
import asyncio

from app.auth import configure_authentication
from app.docs import configure_docs
from app.errors import configure_error_handlers
from app.services import configure_services
from app.settings import Settings
from app.templating import configure_templating

from app.middlewares.session_database_store import DatabaseSessionStore


def configure_application(
    services: Container,
    settings: Settings,
) -> Application:
    app = Application(services=services)

    # Configuration des sessions EN PREMIER
    session_store = DatabaseSessionStore(
        cookie_name="session_id",
        session_max_age=86400,  # 24h authentifiés
        anonymous_max_age=3600,  # 1h anonymes
        secure=False,  # True en production avec HTTPS
        same_site="lax",
    )

    # ✅ Activer les sessions (méthode officielle)
    app.use_sessions(session_store)

    # app.middlewares.append(get_trailing_slash_middleware())

    app.serve_files("app/static")
    configure_error_handlers(app)
    configure_authentication(app, settings)
    configure_docs(app, settings)
    configure_templating(app, settings)
    return app


def get_app():
    try:
        return configure_application(*configure_services())
    except Exception as exc:
        return get_diagnostic_app(exc)


app = get_app()
