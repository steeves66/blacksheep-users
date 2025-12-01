"""
LogoutController - Contrôleur pour la déconnexion des utilisateurs

Responsabilités :
- Déconnexion de l'utilisateur
- Suppression des données de session
- Redirection vers la page d'accueil

Routes :
- GET /auth/logout       -> Déconnecter l'utilisateur
"""

import logging

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get

logger = logging.getLogger(__name__)


class LogoutController(Controller):
    """Contrôleur pour la déconnexion des utilisateurs"""

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth/logout"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "logout"

    @get()
    async def logout(self, request: Request) -> Response:
        """
        Déconnecter l'utilisateur et supprimer les données de session

        GET /auth/logout
        """
        # Récupérer l'ID utilisateur avant suppression (pour les logs)
        user_id = request.session.get("_user_id")
        username = request.session.get("username")

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

        if user_id:
            logger.info(
                f"User logged out: user_id={user_id}, username={username or 'unknown'}"
            )

        # Rediriger vers la page de succès de déconnexion
        return redirect("/auth/logout/success")

    @get("/success")
    async def success(self, request: Request) -> Response:
        """
        Page de succès après déconnexion

        GET /auth/logout/success
        """
        return self.view(
            "success",
            model={
                "title": "Déconnexion réussie",
            },
        )
