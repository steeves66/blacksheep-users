"""
ResetPasswordController - Contrôleur pour la réinitialisation du mot de passe

Responsabilités :
- Affichage du formulaire de demande de réinitialisation
- Traitement de la demande de réinitialisation
- Affichage du formulaire de nouveau mot de passe
- Traitement de la réinitialisation du mot de passe
- Gestion des erreurs (token expiré, etc.)

Routes :
- GET  /auth/reset-password/forgot-password          -> Afficher le formulaire de demande
- POST /auth/reset-password/forgot-password          -> Traiter la demande
- GET  /auth/reset-password/reset/{token}            -> Afficher le formulaire de nouveau mot de passe
- POST /auth/reset-password/reset/{token}            -> Traiter la réinitialisation
"""

import logging

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get, post

from domain.auth.reset_password_service import ResetPasswordService
from helpers.decorators import rate_limit

logger = logging.getLogger(__name__)


class ResetPasswordController(Controller):
    """Contrôleur pour la réinitialisation du mot de passe"""

    def __init__(self, reset_password_service: ResetPasswordService):
        self.reset_password_service = reset_password_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth/reset-password"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "reset_password"

    @get("/forgot-password")
    async def forgot_password_form(self, request: Request) -> Response:
        """
        Afficher le formulaire de demande de réinitialisation

        GET /auth/reset-password/forgot-password
        """
        email = (
            request.query.get("email", [""])[0] if request.query.get("email") else ""
        )

        return self.view(
            "forgot_password",
            model={
                "title": "Mot de passe oublié",
                "error": None,
                "form_data": {"email": email},
            },
        )

    @post("/forgot-password")
    @rate_limit(limit=3, per_seconds=900, scope="forgot-password")
    async def forgot_password(self, request: Request) -> Response:
        """
        Traiter la demande de réinitialisation

        POST /auth/reset-password/forgot-password
        """
        try:
            form_data = await request.form()
            email = form_data.get("email", "").strip()

            if not email:
                return self.view(
                    "forgot_password",
                    model={
                        "title": "Mot de passe oublié",
                        "error": "Veuillez saisir votre adresse email",
                        "form_data": {"email": email},
                    },
                )

            # Demander la réinitialisation
            await self.reset_password_service.request_password_reset(email)

            # Toujours afficher la même page (sécurité)
            return self.view(
                "forgot_password_sent",
                model={
                    "title": "Email envoyé",
                    "email": email,
                },
            )

        except Exception as e:
            logger.error(f"Forgot password error: {e}", exc_info=True)
            return self.view(
                "forgot_password",
                model={
                    "title": "Mot de passe oublié",
                    "error": "Une erreur est survenue. Veuillez réessayer.",
                    "form_data": {"email": email if "email" in locals() else ""},
                },
            )

    @get("/reset/{token}")
    async def reset_password_form(self, token: str) -> Response:
        """
        Afficher le formulaire de nouveau mot de passe

        GET /auth/reset-password/reset/{token}
        """
        # Vérifier la validité du token
        (
            is_valid,
            message,
            user,
        ) = await self.reset_password_service.verify_password_reset_token(token)

        if not is_valid:
            if message == "expired" and user:
                return self.view(
                    "reset_password_expired",
                    model={
                        "title": "Lien expiré",
                        "email": user.email,
                    },
                )

            return self.view(
                "reset_password_error",
                model={
                    "title": "Lien invalide",
                    "message": message,
                },
            )

        return self.view(
            "reset_password",
            model={
                "title": "Nouveau mot de passe",
                "token": token,
                "error": None,
            },
        )

    @post("/reset/{token}")
    async def reset_password(self, token: str, request: Request) -> Response:
        """
        Traiter la réinitialisation du mot de passe

        POST /auth/reset-password/reset/{token}
        """
        try:
            form_data = await request.form()
            new_password = form_data.get("new_password", "")
            confirm_password = form_data.get("confirm_password", "")

            # Validation
            if not new_password or not confirm_password:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Veuillez remplir tous les champs",
                    },
                )

            if new_password != confirm_password:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Les mots de passe ne correspondent pas",
                    },
                )

            if len(new_password) < 8:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Le mot de passe doit contenir au moins 8 caractères",
                    },
                )

            # Réinitialiser le mot de passe
            success, message = await self.reset_password_service.reset_password(
                token, new_password
            )

            if not success:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": message,
                    },
                )

            # Succès : rediriger vers la page de succès
            logger.info("Password reset successful")
            return redirect("/auth/reset-password/success")

        except Exception as e:
            logger.error(f"Reset password error: {e}", exc_info=True)
            return self.view(
                "reset_password",
                model={
                    "title": "Nouveau mot de passe",
                    "token": token,
                    "error": "Une erreur est survenue. Veuillez réessayer.",
                },
            )

    @get("/success")
    async def success(self, request: Request) -> Response:
        """
        Page de succès après réinitialisation

        GET /auth/reset-password/success
        """
        return self.view(
            "reset_password_success",
            model={
                "title": "Mot de passe réinitialisé",
            },
        )
