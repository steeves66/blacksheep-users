"""
ResetPasswordService - Service pour la réinitialisation du mot de passe

Responsabilités :
- Demander une réinitialisation de mot de passe
- Générer et gérer les tokens de réinitialisation
- Vérifier les tokens de réinitialisation
- Réinitialiser le mot de passe
- Logique métier de la réinitialisation

Ne fait PAS :
- Envoi direct d'emails (délégué à EmailService)
- Accès direct à la base de données (délégué au repository)
"""

import asyncio
import logging
from secrets import token_urlsafe
from typing import Optional, Tuple

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.settings import Settings
from domain.email_service import EmailService
from model.user import User
from repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)


class ResetPasswordService:
    """Service pour la réinitialisation du mot de passe"""

    def __init__(
        self,
        settings: Settings,
        user_repo: UserRepository,
        email_service: EmailService,
    ):
        self.settings = settings
        self.user_repo = user_repo
        self.email_service = email_service

    async def request_password_reset(self, email: str) -> bool:
        """
        Demander une réinitialisation de mot de passe

        Flux:
        1. Vérifier que l'utilisateur existe
        2. Générer un token aléatoire
        3. Enregistrer le token en base
        4. Signer le token
        5. Envoyer l'email avec le lien

        Args:
            email: Email de l'utilisateur

        Returns:
            True si l'email a été envoyé (ou si l'email n'existe pas - pour la sécurité)

        Note:
            Retourne toujours True pour éviter l'énumération des comptes
            (ne pas révéler si un email existe ou non)
        """
        try:
            # 1. Récupérer l'utilisateur
            user = await self.user_repo.get_user_by_email(email)

            # Si l'utilisateur n'existe pas, on fait semblant d'envoyer l'email
            # (sécurité: ne pas révéler l'existence du compte)
            if not user:
                logger.warning(
                    f"Password reset requested for non-existent email: {email}"
                )
                # Simuler un délai pour éviter le timing attack
                await asyncio.sleep(0.5)
                return True

            # 2. Supprimer les anciens tokens de cet utilisateur
            await self.user_repo.delete_user_password_reset_tokens(user.id)

            # 3. Générer un nouveau token
            raw_token = self._generate_token()

            # 4. Enregistrer le token en base (expiration: 1h)
            await self.user_repo.create_password_reset_token(
                user_id=user.id,
                token=raw_token,
                expiry_hours=1,  # Token valide 1 heure
            )

            # 5. Signer le token
            signed_token = self._sign_token(user.id, raw_token)

            # 6. Construire l'URL et envoyer l'email
            reset_url = f"{self.settings.verification.base_url}/auth/reset-password/reset/{signed_token}"

            email_sent = await self.email_service.send_password_reset_email(
                to=user.email, reset_link=reset_url, username=user.username
            )

            if not email_sent:
                logger.warning(f"Failed to send password reset email to {email}")
            else:
                logger.info(f"Password reset email sent to: {email}")

            return True

        except Exception as e:
            logger.error(
                f"Password reset request failed for {email}: {e}", exc_info=True
            )
            return True  # Retourner True même en cas d'erreur (sécurité)

    async def verify_password_reset_token(
        self, signed_token: str
    ) -> Tuple[bool, str, Optional[User]]:
        """
        Vérifier la validité d'un token de réinitialisation

        Returns:
            Tuple (is_valid, message, user)
            - (True, "valid", User) si le token est valide
            - (False, "expired", User) si le token a expiré
            - (False, "invalid", None) si le token est invalide
        """
        try:
            # 1. Désigner le token
            serializer = URLSafeTimedSerializer(self.settings.verification.secret)

            try:
                user_id, raw_token = serializer.loads(
                    signed_token,
                    max_age=3600,  # 1 heure en secondes
                )
            except SignatureExpired:
                logger.warning("Password reset token expired")
                try:
                    user_id, raw_token = serializer.loads_unsafe(signed_token)
                    user = await self.user_repo.get_user_by_id(user_id)
                    return False, "expired", user
                except Exception:
                    return False, "Le lien a expiré", None
            except BadSignature:
                logger.warning("Invalid password reset token signature")
                return False, "Le lien est invalide", None

            # 2. Récupérer le token en base
            token = await self.user_repo.get_password_reset_token(
                user_id, raw_token, only_valid=True
            )

            if not token:
                logger.warning("Password reset token not found or already used")
                return False, "Ce lien n'est plus valide", None

            # 3. Récupérer l'utilisateur
            user = await self.user_repo.get_user_by_id(user_id)

            if not user:
                logger.error(f"User not found for password reset: user_id={user_id}")
                return False, "Utilisateur introuvable", None

            logger.info(f"Password reset token verified: user_id={user_id}")
            return True, "valid", user

        except Exception as e:
            logger.error(f"Error verifying password reset token: {e}", exc_info=True)
            return False, "Une erreur est survenue", None

    async def reset_password(
        self, signed_token: str, new_password: str
    ) -> Tuple[bool, str]:
        """
        Réinitialiser le mot de passe d'un utilisateur

        Args:
            signed_token: Token signé reçu par email
            new_password: Nouveau mot de passe en clair

        Returns:
            Tuple (success, message)
        """
        try:
            # 1. Vérifier le token
            is_valid, message, user = await self.verify_password_reset_token(
                signed_token
            )

            if not is_valid or not user:
                return False, message

            # 2. Récupérer le token non signé
            serializer = URLSafeTimedSerializer(self.settings.verification.secret)
            user_id, raw_token = serializer.loads(signed_token, max_age=3600)

            token = await self.user_repo.get_password_reset_token(
                user_id, raw_token, only_valid=True
            )

            if not token:
                return False, "Token invalide ou déjà utilisé"

            # 3. Hasher le nouveau mot de passe
            hashed_password = await self._async_hash_password(new_password)

            # 4. Mettre à jour le mot de passe
            updated_user = await self.user_repo.update_user_password(
                user.id, hashed_password
            )

            if not updated_user:
                return False, "Erreur lors de la mise à jour du mot de passe"

            # 5. Marquer le token comme utilisé
            await self.user_repo.mark_password_reset_token_as_used(token.id)

            # 6. Supprimer tous les autres tokens de reset
            await self.user_repo.delete_user_password_reset_tokens(user.id)

            logger.info(
                f"Password reset successful: user_id={user.id}, email={user.email}"
            )
            return True, "Votre mot de passe a été réinitialisé avec succès"

        except Exception as e:
            logger.error(f"Password reset failed: {e}", exc_info=True)
            return False, "Une erreur est survenue lors de la réinitialisation"

    # ==========================================
    # MÉTHODES UTILITAIRES
    # ==========================================

    async def _async_hash_password(self, password: str) -> str:
        """Hash un mot de passe de manière asynchrone"""
        password_bytes = password.encode("utf-8")
        hashed = await asyncio.to_thread(
            bcrypt.hashpw, password_bytes, bcrypt.gensalt()
        )
        return hashed.decode("utf-8")

    def _generate_token(self) -> str:
        """Générer un token aléatoire cryptographiquement sûr"""
        return token_urlsafe(32)

    def _sign_token(self, user_id: int, token: str) -> str:
        """Signer un token avec itsdangerous"""
        serializer = URLSafeTimedSerializer(self.settings.verification.secret)
        return serializer.dumps([user_id, token])
