"""
AuthController - Contrôleur pour l'authentification (login + logout)

Responsabilités :
- Affichage du formulaire de connexion
- Traitement de l'authentification
- Gestion de la session utilisateur
- Déconnexion
- Redirection après connexion/déconnexion
- Gestion des erreurs (compte non activé, identifiants incorrects)

Routes :
- GET  /auth/login              -> Afficher le formulaire de connexion
- POST /auth/login              -> Traiter la connexion
- GET  /auth/login/success      -> Page de succès de connexion
- GET  /auth/logout             -> Déconnecter l'utilisateur
- GET  /auth/logout/success     -> Page de succès de déconnexion
"""

import logging
from datetime import UTC, datetime

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get, post

from domain.auth.auth_service import AuthService
from helpers.decorators import rate_limit

logger = logging.getLogger(__name__)


class AuthController(Controller):
    """Contrôleur pour l'authentification (login + logout)"""

    def __init__(self, auth_service: AuthService):
        self.auth_service = auth_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "auth"

    # ==========================================
    # LOGIN
    # ==========================================

    @get("/login")
    async def login_form(self, request: Request) -> Response:
        """
        Afficher le formulaire de connexion

        GET /auth/login
        """
        # Récupérer un éventuel message de succès (ex: après inscription)
        message = request.query.get("message", [""])[0]
        success = request.query.get("success", [""])[0]

        return self.view(
            "login/login",
            model={
                "title": "Connexion",
                "error": None,
                "success": success,
                "message": message,
                "identifier": "",
            },
        )

    @post("/login")
    @rate_limit(limit=5, per_seconds=300, scope="login")
    async def login(self, request: Request) -> Response:
        """
        Traiter la connexion d'un utilisateur

        POST /auth/login
        """
        try:
            # Récupérer les données du formulaire
            form_data = await request.form()
            identifier = form_data.get("identifier", "").strip()  # email ou username
            password = form_data.get("password", "")

            # Validation
            if not identifier or not password:
                return self.view(
                    "login/login",
                    model={
                        "title": "Connexion",
                        "error": "Veuillez renseigner tous les champs",
                        "identifier": identifier or "",
                        "success": None,
                        "message": "",
                    },
                )

            # Authentifier l'utilisateur
            user = await self.auth_service.authenticate_user(identifier, password)

            if not user:
                return self.view(
                    "login/login",
                    model={
                        "title": "Connexion",
                        "error": "Identifiants incorrects",
                        "identifier": identifier,
                        "success": None,
                        "message": "",
                    },
                )

            # Stocker l'utilisateur dans la session
            request.session["_user_id"] = user.id
            request.session["username"] = user.username
            request.session["email"] = user.email
            request.session["authenticated_at"] = datetime.now(UTC).isoformat()

            logger.info(f"User logged in: user_id={user.id}, email={user.email}")

            # Rediriger vers une page de succès
            return redirect(f"/auth/login/success?username={user.username}")

        except ValueError as e:
            # Compte non activé
            logger.warning(f"Login failed: {str(e)}")
            return self.view(
                "login/login",
                model={
                    "title": "Connexion",
                    "error": str(e),
                    "identifier": identifier,
                    "can_resend": True,  # Permettre de renvoyer l'email
                    "success": None,
                    "message": "",
                },
            )

        except Exception as e:
            logger.error(f"Login failed - server error: {str(e)}", exc_info=True)
            return self.view(
                "login/login",
                model={
                    "title": "Connexion",
                    "error": "Une erreur est survenue lors de la connexion",
                    "identifier": identifier,
                    "success": None,
                    "message": "",
                },
            )

    @get("/login/success")
    async def login_success(self, request: Request) -> Response:
        """
        Page de succès après connexion

        GET /auth/login/success?username=...
        """
        username = request.query.get("username", [""])[0]

        return self.view(
            "login/login_success",
            model={
                "title": "Connexion réussie",
                "username": username,
            },
        )

    # ==========================================
    # LOGOUT
    # ==========================================

    @get("/logout")
    async def logout(self, request: Request) -> Response:
        """
        Déconnecter l'utilisateur et supprimer les données de session

        GET /auth/logout
        """
        # Récupérer l'ID utilisateur avant suppression (pour les logs)
        user_id = request.session.get("_user_id")
        username = request.session.get("username")

        # Utiliser le service pour logger la déconnexion
        if user_id and username:
            self.auth_service.prepare_logout(user_id, username)

        # Supprimer toutes les données de session liées à l'utilisateur
        session_keys_to_delete = [
            "_user_id",
            "username",
            "email",
            "authenticated_at",
        ]

        for key in session_keys_to_delete:
            if key in request.session:
                del request.session[key]

        # Rediriger vers la page de succès de déconnexion
        return redirect("/auth/logout/success")

    @get("/logout/success")
    async def logout_success(self, request: Request) -> Response:
        """
        Page de succès après déconnexion

        GET /auth/logout/success
        """
        return self.view(
            "logout/logout_success",
            model={
                "title": "Déconnexion réussie",
            },
        )
