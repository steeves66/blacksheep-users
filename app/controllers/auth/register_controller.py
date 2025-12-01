"""
RegisterController - Contrôleur pour l'inscription simple sans vérification email

Responsabilités :
- Affichage du formulaire d'inscription
- Traitement de l'inscription
- Validation des entrées
- Redirection après succès

Routes :
- GET  /auth/register       -> Afficher le formulaire
- POST /auth/register       -> Traiter l'inscription
"""

import logging

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get, post

from domain.auth.register_service import RegisterService
from helpers.decorators import rate_limit

logger = logging.getLogger(__name__)


class RegisterController(Controller):
    """
    Contrôleur pour l'inscription simple (sans vérification email)
    L'utilisateur est actif immédiatement après inscription
    """

    def __init__(self, register_service: RegisterService):
        self.register_service = register_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth/register"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "register"

    @get()
    async def register_form(self, request: Request) -> Response:
        """
        Afficher le formulaire d'inscription simple

        GET /auth/register
        """
        return self.view(
            model={
                "title": "Inscription",
                "error": None,
                "form_data": {},
            }
        )

    @post()
    @rate_limit(limit=5, per_seconds=3600, scope="register")
    async def register(self, request: Request) -> Response:
        """
        Traiter l'inscription simple (utilisateur actif immédiatement)

        POST /auth/register
        """
        try:
            # Récupérer les données du formulaire
            form_data = await request.form()
            username = form_data.get("username", "").strip()
            email = form_data.get("email", "").strip()
            password = form_data.get("password", "")
            confirm_password = form_data.get("confirm_password", "")

            # Validation
            if not username or not email or not password:
                return self.view(
                    model={
                        "title": "Inscription",
                        "error": "Tous les champs sont requis",
                        "form_data": {
                            "username": username,
                            "email": email,
                        },
                    }
                )

            if password != confirm_password:
                return self.view(
                    model={
                        "title": "Inscription",
                        "error": "Les mots de passe ne correspondent pas",
                        "form_data": {
                            "username": username,
                            "email": email,
                        },
                    }
                )

            if len(password) < 8:
                return self.view(
                    model={
                        "title": "Inscription",
                        "error": "Le mot de passe doit contenir au moins 8 caractères",
                        "form_data": {
                            "username": username,
                            "email": email,
                        },
                    }
                )

            # Créer l'utilisateur
            user = await self.register_service.create_simple_user(
                username=username, email=email, password=password
            )

            logger.info(f"User registered successfully: {user.email}")

            # Rediriger vers la page de succès
            return redirect(
                f"/auth/register/success?username={user.username}&email={user.email}"
            )

        except ValueError as e:
            logger.warning(f"Registration failed: {str(e)}")
            return self.view(
                model={
                    "title": "Inscription",
                    "error": str(e),
                    "form_data": {
                        "username": username if "username" in locals() else "",
                        "email": email if "email" in locals() else "",
                    },
                }
            )

        except Exception as e:
            logger.error(f"Registration failed - server error: {str(e)}", exc_info=True)
            return self.view(
                model={
                    "title": "Inscription",
                    "error": "Une erreur est survenue lors de l'inscription",
                    "form_data": {
                        "username": username if "username" in locals() else "",
                        "email": email if "email" in locals() else "",
                    },
                }
            )

    @get("/success")
    async def success(self, request: Request) -> Response:
        """
        Page de succès après inscription

        GET /auth/register/success?username=...&email=...
        """
        username = request.query.get("username", [""])[0]
        email = request.query.get("email", [""])[0]

        return self.view(
            "success",
            model={
                "title": "Inscription réussie",
                "username": username,
                "email": email,
            },
        )
