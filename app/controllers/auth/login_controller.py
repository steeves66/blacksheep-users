"""
LoginController - Contrôleur pour la connexion des utilisateurs

Responsabilités :
- Affichage du formulaire de connexion
- Traitement de l'authentification
- Gestion de la session utilisateur
- Redirection après connexion
- Gestion des erreurs (compte non activé, identifiants incorrects)

Routes :
- GET  /auth/login       -> Afficher le formulaire de connexion
- POST /auth/login       -> Traiter la connexion
"""

import logging
from datetime import UTC, datetime

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get, post

from domain.auth.login_service import LoginService
from helpers.decorators import rate_limit

logger = logging.getLogger(__name__)


class LoginController(Controller):
    """Contrôleur pour l'authentification des utilisateurs"""

    def __init__(self, login_service: LoginService):
        self.login_service = login_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth/login"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "login"

    @get()
    async def login_form(self, request: Request) -> Response:
        """
        Afficher le formulaire de connexion

        GET /auth/login
        """
        # Récupérer un éventuel message de succès (ex: après inscription)
        message = request.query.get("message", [""])[0]
        success = request.query.get("success", [""])[0]

        return self.view(
            model={
                "title": "Connexion",
                "error": None,
                "success": success,
                "message": message,
                "identifier": "",
            }
        )

    @post()
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
                    model={
                        "title": "Connexion",
                        "error": "Veuillez renseigner tous les champs",
                        "identifier": identifier or "",
                        "success": None,
                        "message": "",
                    }
                )

            # Authentifier l'utilisateur
            user = await self.login_service.authenticate_user(identifier, password)

            if not user:
                return self.view(
                    model={
                        "title": "Connexion",
                        "error": "Identifiants incorrects",
                        "identifier": identifier,
                        "success": None,
                        "message": "",
                    }
                )

            # Stocker l'utilisateur dans la session
            request.session["_user_id"] = user.id
            request.session["username"] = user.username
            request.session["email"] = user.email
            request.session["authenticated_at"] = datetime.now(UTC).isoformat()

            logger.info(f"User logged in: user_id={user.id}, email={user.email}")

            # Rediriger vers une page de succès ou dashboard
            return redirect(f"/auth/login/success?username={user.username}")

        except ValueError as e:
            # Compte non activé
            logger.warning(f"Login failed: {str(e)}")
            return self.view(
                model={
                    "title": "Connexion",
                    "error": str(e),
                    "identifier": identifier,
                    "can_resend": True,  # Permettre de renvoyer l'email
                    "success": None,
                    "message": "",
                }
            )

        except Exception as e:
            logger.error(f"Login failed - server error: {str(e)}", exc_info=True)
            return self.view(
                model={
                    "title": "Connexion",
                    "error": "Une erreur est survenue lors de la connexion",
                    "identifier": identifier,
                    "success": None,
                    "message": "",
                }
            )

    @get("/success")
    async def success(self, request: Request) -> Response:
        """
        Page de succès après connexion

        GET /auth/login/success?username=...
        """
        username = request.query.get("username", [""])[0]

        return self.view(
            "success",
            model={
                "title": "Connexion réussie",
                "username": username,
            },
        )
