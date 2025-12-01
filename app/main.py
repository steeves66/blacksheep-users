# """
# This module configures the BlackSheep application before it starts.
# """

# import asyncio

# from blacksheep import Application

# # ⭐ NOUVEAUX IMPORTS POUR LA SÉCURITÉ
# # ⭐ NOUVEAUX IMPORTS POUR LA SÉCURITÉ
# from blacksheep.server.csrf import use_anti_forgery
# from blacksheep.server.diagnostics import get_diagnostic_app
# from blacksheep.server.env import is_development
# from blacksheep.server.redirects import get_trailing_slash_middleware
# from blacksheep.server.security.hsts import HSTSMiddleware
# from blacksheepsqlalchemy import use_sqlalchemy
# from rodi import Container

# from app.auth import configure_authentication
# from app.docs import configure_docs
# from app.errors import configure_error_handlers
# from app.services import configure_services
# from app.settings import Settings
# from app.templating import configure_templating
# from dbsession import AsyncSessionLocal
# from domain.email_service import EmailService
# from domain.user_service import UserService
# from middlewares.http_session_middleware import HttpSessionStoreMiddleware
# from repositories.user_repository import UserRepository


# def configure_application(
#     services: Container,
#     settings: Settings,
# ) -> Application:
#     app = Application(services=services)

#     # Configuration des sessions EN PREMIER
#     session_store = HttpSessionStoreMiddleware(
#         cookie_name="session_id",
#         session_max_age=86400,  # 24h authentifiés
#         anonymous_max_age=3600,  # 1h anonymes
#         secure=False,  # True en production avec HTTPS
#         same_site="lax",
#     )

#     # ✅ Activer les sessions (méthode officielle)
#     app.use_sessions(session_store)

#     # app.middlewares.append(get_trailing_slash_middleware())

#     # Configure DI for sqlalchemy session
#     use_sqlalchemy(
#         app, connection_string=settings.database.url, echo=settings.database.echo
#     )

#     # Add domain services for DI
#     app.services.add_transient(EmailService)
#     app.services.add_scoped(UserRepository)
#     app.services.add_scoped(UserService)

#     app.serve_files("app/static")
#     configure_error_handlers(app)
#     configure_authentication(app, settings)
#     configure_docs(app, settings)
#     configure_templating(app, settings)
#     return app


# def get_app():
#     try:
#         return configure_application(*configure_services())
#     except Exception as exc:
#         return get_diagnostic_app(exc)


# app = get_app()


"""
This module configures the BlackSheep application before it starts.
"""

import asyncio
import logging

from blacksheep import Application

# ⭐ NOUVEAUX IMPORTS POUR LA SÉCURITÉ
from blacksheep.server.csrf import use_anti_forgery
from blacksheep.server.diagnostics import get_diagnostic_app
from blacksheep.server.env import is_development
from blacksheep.server.redirects import get_trailing_slash_middleware
from blacksheep.server.security.hsts import HSTSMiddleware
from blacksheepsqlalchemy import use_sqlalchemy
from rodi import Container

from app.auth import configure_authentication
from app.docs import configure_docs
from app.errors import configure_error_handlers
from app.services import configure_services
from app.settings import Settings, load_settings
from app.templating import configure_templating
from dbsession import AsyncSessionLocal
from domain.email_service import EmailService
from domain.user_service import UserService
from middlewares.http_session_middleware import HttpSessionStoreMiddleware
from repositories.user_repository import UserRepository

# ⭐ NOUVEAUX IMPORTS - Architecture modulaire d'authentification
from repositories.auth import (
    RegisterRepository,
    RegisterVerifiedRepository,
    AuthRepository,
    ResetPasswordRepository,
)
from domain.auth import (
    RegisterService,
    RegisterVerifiedService,
    AuthService,
    ResetPasswordService,
)

logger = logging.getLogger(__name__)


def configure_security(app: Application, settings: Settings):
    """
    Configure toutes les couches de sécurité

    - CORS (Cross-Origin Resource Sharing)
    - CSRF/Anti-Forgery (Cross-Site Request Forgery)
    - HSTS (HTTP Strict Transport Security)
    - Headers de sécurité

    ⚠️ IMPORTANT : Doit être appelé APRÈS configure_templating()
    """

    logger.info("🔒 Configuration de la sécurité...")

    # ==========================================
    # 1. HEADERS DE SÉCURITÉ
    # ==========================================

    @app.on_middlewares_configuration
    def configure_security_headers_middleware(application: Application):
        """Middleware pour ajouter les headers de sécurité HTTP"""

        async def security_headers_middleware(request, handler):
            response = await handler(request)

            # Empêcher le sniffing MIME
            response.add_header(b"X-Content-Type-Options", b"nosniff")

            # Empêcher l'affichage dans des iframes (clickjacking)
            response.add_header(b"X-Frame-Options", b"DENY")

            # Protection XSS (navigateurs anciens)
            response.add_header(b"X-XSS-Protection", b"1; mode=block")

            # Politique de referrer
            response.add_header(b"Referrer-Policy", b"strict-origin-when-cross-origin")

            # Désactiver certaines API du navigateur
            response.add_header(
                b"Permissions-Policy", b"geolocation=(), microphone=(), camera=()"
            )

            return response

        application.middlewares.append(security_headers_middleware)

    logger.info("   ✓ Headers de sécurité configurés")

    # ==========================================
    # 2. CORS (Cross-Origin Resource Sharing)
    # ==========================================

    if is_development():
        # DÉVELOPPEMENT : Configuration permissive
        app.use_cors(
            allow_methods="*",
            allow_origins="*",  # Accepte tous les origins en dev
            allow_headers="* Authorization Content-Type",
            max_age=3600,
            allow_credentials=True,
        )
        logger.info("   ✓ CORS (développement - permissif)")
    else:
        # PRODUCTION : Configuration restrictive
        allowed_origins = settings.security.cors_allowed_origins

        app.use_cors(
            allow_methods="GET POST PUT DELETE PATCH",
            allow_origins=" ".join(allowed_origins),
            allow_headers="Authorization Content-Type X-Requested-With",
            max_age=86400,  # 24h
            allow_credentials=True,
        )
        logger.info(f"   ✓ CORS (production - {len(allowed_origins)} origins)")

    # Politiques CORS spécifiques
    app.add_cors_policy(
        "public_api",
        allow_methods="GET",
        allow_origins="*",
    )

    # API admin restrictive (seulement en production)
    if not is_development():
        admin_origins = settings.security.cors_admin_origins
        app.add_cors_policy(
            "admin_api",
            allow_methods="GET POST PUT DELETE",
            allow_origins=" ".join(admin_origins),
            allow_headers="Authorization Content-Type",
            max_age=3600,
            allow_credentials=True,
        )

    app.add_cors_policy(
        "deny",
        allow_methods="",
        allow_origins="",
    )

    logger.info("   ✓ Politiques CORS (public_api, admin_api, deny)")

    # ==========================================
    # 3. HSTS (HTTP Strict Transport Security)
    # ==========================================

    if not is_development():
        # HSTS seulement en production
        app.middlewares.append(
            HSTSMiddleware(
                max_age=settings.security.hsts_max_age,
                include_sub_domains=settings.security.hsts_include_subdomains,
            )
        )
        logger.info(f"   ✓ HSTS (max-age={settings.security.hsts_max_age})")
    else:
        logger.info("   ⊘ HSTS désactivé (développement)")

    # ==========================================
    # 4. CSRF / ANTI-FORGERY
    # ==========================================

    if settings.security.uses_only_bearer_auth:
        logger.info("   ⊘ CSRF désactivé (Bearer auth uniquement)")
    else:
        # Activer la protection CSRF
        use_anti_forgery(app)
        logger.info("   ✓ CSRF/Anti-Forgery (double-token)")
        logger.info("      → Utilisez {% af_input %} dans vos formulaires POST")

    logger.info("✅ Sécurité configurée")


def configure_application(
    services: Container,
    settings: Settings,
) -> Application:
    """
    Configure l'application BlackSheep

    ORDRE D'INITIALISATION (IMPORTANT) :
    1. Application de base
    2. Sessions
    3. Base de données (SQLAlchemy)
    4. Services (DI)
    5. Fichiers statiques
    6. Gestion d'erreurs
    7. Authentification
    8. Documentation OpenAPI
    9. Templating (Jinja2)
    10. ⭐ SÉCURITÉ (CORS, CSRF, HSTS, headers)
    """

    logger.info("🚀 Configuration de l'application BlackSheep...")

    app = Application(services=services)

    # ==========================================
    # 1. SESSIONS
    # ==========================================

    session_store = HttpSessionStoreMiddleware(
        cookie_name="session_id",
        session_max_age=86400,  # 24h authentifiés
        anonymous_max_age=3600,  # 1h anonymes
        secure=not is_development(),  # ⭐ True en production avec HTTPS
        same_site="lax",  # ⭐ Protection CSRF additionnelle
    )

    app.use_sessions(session_store)
    logger.info("✓ Sessions configurées")

    # ==========================================
    # 2. BASE DE DONNÉES (SQLAlchemy)
    # ==========================================

    use_sqlalchemy(
        app, connection_string=settings.database.url, echo=settings.database.echo
    )
    logger.info("✓ Base de données configurée")

    # ==========================================
    # 3. SERVICES (Dependency Injection)
    # ==========================================

    # Services métier (anciens - à migrer progressivement)
    app.services.add_transient(EmailService)
    app.services.add_scoped(UserRepository)
    app.services.add_scoped(UserService)

    # ⭐ NOUVEAUX SERVICES - Architecture modulaire d'authentification
    # Repositories (scoped - une instance par requête)
    app.services.add_scoped(RegisterRepository)
    app.services.add_scoped(RegisterVerifiedRepository)
    app.services.add_scoped(AuthRepository)
    app.services.add_scoped(ResetPasswordRepository)

    # Services d'authentification
    app.services.add_scoped(RegisterService)
    app.services.add_scoped(RegisterVerifiedService)
    app.services.add_scoped(AuthService)
    app.services.add_scoped(ResetPasswordService)

    logger.info("✓ Services (DI) configurés")
    logger.info("   - Anciens services : EmailService, UserRepository, UserService")
    logger.info("   - Nouveaux repositories : 4 (RegisterRepository, RegisterVerifiedRepository, AuthRepository, ResetPasswordRepository)")
    logger.info("   - Nouveaux services : 4 (RegisterService, RegisterVerifiedService, AuthService, ResetPasswordService)")

    # ==========================================
    # 4. FICHIERS STATIQUES
    # ==========================================

    app.serve_files("app/static")
    logger.info("✓ Fichiers statiques configurés")

    # ==========================================
    # 5. GESTION D'ERREURS
    # ==========================================

    configure_error_handlers(app)
    logger.info("✓ Gestion d'erreurs configurée")

    # ==========================================
    # 6. AUTHENTIFICATION
    # ==========================================

    configure_authentication(app, settings)
    logger.info("✓ Authentification configurée")

    # ==========================================
    # 7. DOCUMENTATION OPENAPI
    # ==========================================

    configure_docs(app, settings)
    logger.info("✓ Documentation OpenAPI configurée")

    # ==========================================
    # 8. TEMPLATING (Jinja2)
    # ==========================================

    configure_templating(app, settings)
    logger.info("✓ Templating (Jinja2) configuré")

    # ==========================================
    # 9. ⭐ SÉCURITÉ (CORS, CSRF, HSTS, headers)
    # ==========================================

    # ⚠️ IMPORTANT : Doit être APRÈS configure_templating()
    # car use_anti_forgery() configure les extensions Jinja2

    configure_security(app, settings)

    # ==========================================
    # TERMINÉ
    # ==========================================

    logger.info("")
    logger.info("✅ Application configurée avec succès")
    logger.info(
        f"   Environnement : {'développement' if is_development() else 'production'}"
    )
    logger.info(f"   Base URL : {settings.verification.base_url}")
    logger.info(f"   CORS origins : {len(settings.security.cors_allowed_origins)}")
    logger.info(
        f"   CSRF : {'désactivé' if settings.security.uses_only_bearer_auth else 'activé'}"
    )
    logger.info("")

    return app


def get_app():
    """Point d'entrée de l'application"""
    try:
        return configure_application(*configure_services())
    except Exception as exc:
        return get_diagnostic_app(exc)


app = get_app()
