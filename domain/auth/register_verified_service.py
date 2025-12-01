"""
RegisterVerifiedService - Service pour l'inscription avec vérification email

Responsabilités :
- Créer un utilisateur inactif
- Générer et gérer les tokens de vérification
- Vérifier l'email
- Renvoyer les emails de vérification
- Activer le compte après vérification
- Envoyer des emails de confirmation, remerciement et bienvenue

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
from repositories.auth.register_verified_repository import RegisterVerifiedRepository

logger = logging.getLogger(__name__)


class RegisterVerifiedService:
    """Service pour l'inscription avec vérification email"""

    def __init__(
        self,
        settings: Settings,
        register_verified_repo: RegisterVerifiedRepository,
        email_service: EmailService,
    ):
        self.settings = settings
        self.register_verified_repo = register_verified_repo
        self.email_service = email_service

    async def create_user(
        self, username: str, email: str, password: str
    ) -> Tuple[User, bool]:
        """
        Inscrire un nouvel utilisateur avec vérification email

        Flux complet :
        1. Vérifier que l'email n'existe pas déjà
        2. Hasher le mot de passe
        3. Créer l'utilisateur (is_active=False)
        4. Envoyer email de confirmation de création de compte
        5. Générer un token aléatoire
        6. Enregistrer le token en base
        7. Signer le token avec itsdangerous
        8. Envoyer l'email de vérification avec le lien

        Args:
            username: Nom d'utilisateur
            email: Email de l'utilisateur
            password: Mot de passe en clair (sera hashé)

        Returns:
            Tuple (User créé, booléan indiquant si l'email a été envoyé)

        Raises:
            ValueError: Si l'email existe déjà
            Exception: Pour les autres erreurs
        """
        try:
            # Étape 1 : Vérifier l'unicité de l'email
            if await self.register_verified_repo.user_exists(email):
                raise ValueError(f"Un utilisateur avec l'email {email} existe déjà")

            # Étape 2 : Hasher le mot de passe avec bcrypt
            hashed_password = await self._async_hash_password(password)

            # Étape 3 : Créer l'utilisateur (inactif par défaut)
            user = await self.register_verified_repo.create_user(
                email=email,
                username=username,
                hashed_password=hashed_password,
                is_active=False,  # Sera activé après vérification email
            )

            logger.info(f"User registered: id={user.id}, email={email}")

            # Étape 4 : Envoyer email de confirmation de création de compte
            await self.email_service.send_account_creation_confirmation(
                to=user.email, username=username
            )

            # Étape 5 : Générer un token aléatoire cryptographiquement sûr
            raw_token = self._generate_token()

            # Étape 6 : Enregistrer le token en base de données
            await self.register_verified_repo.create_verification_token(
                user_id=user.id,
                token=raw_token,
                expiry_delay=self.settings.verification.token_expiry_delay,
            )

            # Étape 7 : Signer le token (user_id + token)
            signed_token = self._sign_token(user.id, raw_token)

            # Étape 8 : Construire l'URL et envoyer l'email de vérification
            verification_url = f"{self.settings.verification.base_url}/auth/register-verified/verify-email/{signed_token}"
            email_sent = await self.email_service.send_verification_email(
                to=user.email, verification_link=verification_url, username=username
            )

            if not email_sent:
                logger.warning(f"Failed to send verification email to {email}")
                logger.info(
                    "Development hint: use this verification link to activate the account: %s",
                    verification_url,
                )

            return user, email_sent

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Registration failed for {email}: {str(e)}")
            raise

    async def verify_email(
        self, signed_token: str
    ) -> Tuple[bool, str, Optional[User]]:
        """
        Vérifier l'email d'un utilisateur

        Flux complet :
        1. Désigner le token signé
        2. Récupérer le token en base
        3. Vérifier la validité du token
        4. Activer l'utilisateur
        5. Envoyer email de remerciement et bienvenue

        Returns:
            Tuple (success, message, user)
        """
        try:
            logger.info(
                f"Starting email verification for token: {signed_token[:20]}..."
            )

            # ÉTAPE 1 : Désigner le token
            serializer = URLSafeTimedSerializer(self.settings.verification.secret)

            try:
                user_id, raw_token = serializer.loads(
                    signed_token,
                    max_age=self.settings.verification.token_expiry_delay * 3600,
                )
                logger.info(f"Token deserialized successfully: user_id={user_id}")
            except SignatureExpired:
                logger.warning("Verification token expired")
                try:
                    user_id, raw_token = serializer.loads_unsafe(signed_token)
                    user = await self.register_verified_repo.get_user_by_id(user_id)
                    return False, "expired", user
                except Exception as ex:
                    logger.error(f"Error loading expired token: {ex}", exc_info=True)
                    return (
                        False,
                        "Le lien de vérification a expiré. Veuillez demander un nouveau lien.",
                        None,
                    )
            except BadSignature as e:
                logger.warning(f"Invalid verification token signature: {e}")
                return False, "Le lien de vérification est invalide.", None

            # ÉTAPE 2 : Récupérer le token en base
            logger.info(f"Looking for token in database: user_id={user_id}")
            token = await self.register_verified_repo.get_verification_token(
                user_id, raw_token, only_valid=True
            )

            if not token:
                logger.warning(f"Token not found or already used: user_id={user_id}")
                user = await self.register_verified_repo.get_user_by_id(user_id)

                if user and user.is_active:
                    return False, "already_active", user
                return False, "Ce lien de vérification n'est plus valide.", None

            logger.info(f"Token found in database: token_id={token.id}")

            # ÉTAPE 3 : Récupérer l'utilisateur
            user = await self.register_verified_repo.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: user_id={user_id}")
                return False, "Utilisateur introuvable.", None

            logger.info(f"User found: user_id={user.id}, is_active={user.is_active}")

            # ÉTAPE 4 : Vérifier si déjà actif
            if user.is_active:
                logger.info(f"User already active: user_id={user_id}")
                await self.register_verified_repo.mark_token_as_used(token.id)
                await self.register_verified_repo.delete_user_tokens(user_id)
                return True, "already_active", user

            # ÉTAPE 5 : Marquer le token comme utilisé
            logger.info(f"Marking token as used: token_id={token.id}")
            await self.register_verified_repo.mark_token_as_used(token.id)

            # ÉTAPE 6 : Supprimer tous les autres tokens
            logger.info(f"Deleting other tokens for user: user_id={user_id}")
            await self.register_verified_repo.delete_user_tokens(user_id)

            # ÉTAPE 7 : Activer l'utilisateur
            logger.info(f"Activating user: user_id={user_id}")
            activated_user = await self.register_verified_repo.activate_user(user_id)

            if not activated_user:
                logger.error(f"Failed to activate user: user_id={user_id}")
                return False, "Erreur lors de l'activation du compte.", None

            # ÉTAPE 8 : Envoyer emails de remerciement et bienvenue
            await self.email_service.send_thank_you_email(
                to=user.email, username=user.username
            )
            await self.email_service.send_welcome_email(
                to=user.email, username=user.username
            )

            logger.info(
                f"User email verified and activated: user_id={user_id}, email={user.email}"
            )
            return True, "Votre compte a été activé avec succès !", activated_user

        except Exception as e:
            logger.error(
                f"Error during email verification: {type(e).__name__}: {e}",
                exc_info=True,
            )
            return (
                False,
                f"Une erreur s'est produite lors de la vérification: {str(e)}",
                None,
            )

    async def resend_verification_email(self, email: str) -> bool:
        """
        Renvoyer un email de vérification

        Args:
            email: Email de l'utilisateur

        Returns:
            True si l'email a été envoyé

        Raises:
            ValueError: Si l'utilisateur n'existe pas ou est déjà activé
        """
        user = await self.register_verified_repo.get_user_by_email(email)

        if not user:
            raise ValueError("Aucun utilisateur trouvé avec cet email")

        if user.is_active:
            raise ValueError("Ce compte est déjà activé")

        # Supprimer les anciens tokens
        await self.register_verified_repo.delete_user_tokens(user.id)

        # Générer un nouveau token
        raw_token = self._generate_token()

        # Enregistrer le nouveau token
        await self.register_verified_repo.create_verification_token(
            user_id=user.id,
            token=raw_token,
            expiry_delay=self.settings.verification.token_expiry_delay,
        )

        # Signer le token
        signed_token = self._sign_token(user.id, raw_token)

        # Envoyer l'email
        verification_url = f"{self.settings.verification.base_url}/auth/register-verified/verify-email/{signed_token}"

        email_sent = await self.email_service.send_resend_verification_email(
            to=user.email, verification_link=verification_url, username=user.username
        )

        logger.info(f"Verification email resent to: {email}")

        return email_sent

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
