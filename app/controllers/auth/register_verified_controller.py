"""
RegisterVerifiedController - Contrôleur pour l'inscription avec vérification email

Responsabilités :
- Affichage du formulaire d'inscription
- Traitement de l'inscription
- Vérification de l'email via token
- Renvoi d'email de vérification
- Gestion des erreurs (token expiré, compte déjà actif, etc.)

Routes :
- GET  /auth/register-verified               -> Afficher le formulaire
- POST /auth/register-verified               -> Traiter l'inscription
- GET  /auth/register-verified/verify-email/{token}  -> Vérifier l'email
- GET  /auth/register-verified/resend-verification   -> Afficher le formulaire de renvoi
- POST /auth/register-verified/resend-verification   -> Renvoyer l'email
- GET  /auth/register-verified/success               -> Page de succès
- GET  /auth/register-verified/account-active        -> Page compte déjà actif
"""

import logging
from urllib.parse import urlencode

from blacksheep import Request, Response, redirect
from blacksheep.server.controllers import Controller, get, post

from domain.auth.register_verified_service import RegisterVerifiedService
from helpers.decorators import rate_limit

logger = logging.getLogger(__name__)


class RegisterVerifiedController(Controller):
    """
    Contrôleur pour l'inscription avec vérification email
    L'utilisateur reçoit un email et doit cliquer sur un lien pour activer son compte
    """

    def __init__(self, register_verified_service: RegisterVerifiedService):
        self.register_verified_service = register_verified_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour ce contrôleur"""
        return "/auth/register-verified"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération des routes"""
        return "register_verified"

    @get()
    async def register_form(self, request: Request) -> Response:
        """
        Afficher le formulaire d'inscription avec vérification email

        GET /auth/register-verified
        """
        return self.view(
            model={
                "title": "Inscription avec vérification email",
                "error": None,
                "form_data": {},
            }
        )

    @post()
    @rate_limit(limit=5, per_seconds=3600, scope="register-verified")
    async def register(self, request: Request) -> Response:
        """
        Traiter l'inscription avec vérification email
        L'utilisateur est créé mais inactif jusqu'à vérification

        POST /auth/register-verified
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

            # Créer l'utilisateur (inactif) et envoyer l'email
            user, email_sent = await self.register_verified_service.create_user(
                username=username, email=email, password=password
            )

            logger.info(f"User registered successfully: {user.email}")

            # Rediriger vers la page de succès
            return self.view(
                "success",
                model={
                    "title": "Inscription réussie",
                    "username": user.username,
                    "email": user.email,
                    "email_sent": email_sent,
                },
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

    @get("/verify-email/{token}")
    async def verify_email(self, token: str) -> Response:
        """
        Vérifier l'email d'un utilisateur à partir du lien reçu

        GET /auth/register-verified/verify-email/{token}
        """
        success, message, user = await self.register_verified_service.verify_email(
            token
        )

        # CAS 1 : Token expiré
        if message == "expired" and user:
            return redirect(
                f"/auth/register-verified/resend-verification?reason=expired&email={user.email}"
            )

        # CAS 2 : Compte déjà activé
        if message == "already_active" and user:
            return redirect(
                f"/auth/register-verified/account-active?email={user.email}"
            )

        # CAS 3 : Succès
        if success:
            params = urlencode(
                {
                    "message": "Votre compte a été activé avec succès ! Vous pouvez maintenant vous connecter.",
                }
            )
            return redirect(f"/auth/login?{params}")

        # CAS 4 : Erreur
        return self.view(
            "verify_error",
            model={
                "title": "Vérification échouée",
                "message": message,
            },
        )

    @get("/resend-verification")
    async def resend_verification_form(self, request: Request) -> Response:
        """
        Afficher le formulaire de renvoi d'email de vérification

        GET /auth/register-verified/resend-verification?reason=expired&email=...
        """
        reason_list = request.query.get("reason", "default")
        email_list = request.query.get("email", "")

        reason = reason_list[0] if reason_list else "default"
        email = email_list[0] if email_list else ""

        messages = {
            "expired": "Votre lien a expiré.",
            "not_received": "Vous n'avez pas reçu l'email ?",
            "login_inactive": "Votre compte n'est pas activé.",
            "default": "Entrez votre email pour recevoir un nouveau lien de vérification.",
        }

        return self.view(
            "resend_verification",
            model={
                "title": "Renvoyer l'email de vérification",
                "context_message": messages.get(reason, messages["default"]),
                "email": email,
                "error": None,
            },
        )

    @post("/resend-verification")
    @rate_limit(limit=3, per_seconds=600, scope="resend-verification")
    async def resend_verification(self, request: Request) -> Response:
        """
        Traiter le renvoi d'email de vérification

        POST /auth/register-verified/resend-verification
        """
        try:
            form_data = await request.form()
            email = form_data.get("email", "").strip()

            if not email:
                return self.view(
                    "resend_verification",
                    model={
                        "title": "Renvoyer l'email de vérification",
                        "error": "L'email est requis",
                        "email": "",
                        "context_message": "Entrez votre email pour recevoir un nouveau lien de vérification.",
                    },
                )

            # Renvoyer l'email
            email_sent = await self.register_verified_service.resend_verification_email(
                email
            )

            if not email_sent:
                logger.error(f"Failed to send verification email to {email}")
                return self.view(
                    "resend_verification",
                    model={
                        "title": "Renvoyer l'email de vérification",
                        "error": "Échec de l'envoi de l'email",
                        "email": email,
                        "context_message": "Entrez votre email pour recevoir un nouveau lien de vérification.",
                    },
                )

            logger.info(f"Verification email resent to: {email}")

            return self.view(
                "resend_success",
                model={
                    "title": "Email renvoyé",
                    "email": email,
                },
            )

        except ValueError as e:
            logger.warning(f"Resend verification failed: {str(e)}")
            return self.view(
                "resend_verification",
                model={
                    "title": "Renvoyer l'email de vérification",
                    "error": str(e),
                    "email": email if "email" in locals() else "",
                    "context_message": "Entrez votre email pour recevoir un nouveau lien de vérification.",
                },
            )

        except Exception as e:
            logger.error(
                f"Resend verification failed - server error: {str(e)}", exc_info=True
            )
            return self.view(
                "resend_verification",
                model={
                    "title": "Renvoyer l'email de vérification",
                    "error": "Une erreur est survenue lors de l'envoi de l'email",
                    "email": email if "email" in locals() else "",
                    "context_message": "Entrez votre email pour recevoir un nouveau lien de vérification.",
                },
            )

    @get("/account-active")
    async def account_active(self, request: Request) -> Response:
        """
        Page informant que le compte est déjà activé

        GET /auth/register-verified/account-active?email=...
        """
        email_list = request.query.get("email")
        email = email_list[0] if email_list else ""

        return self.view(
            "account_active",
            model={
                "title": "Compte déjà activé",
                "email": email,
            },
        )
