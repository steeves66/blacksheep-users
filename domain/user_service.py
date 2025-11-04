"""
UserService - Service principal de gestion des utilisateurs

Responsabilités :
- Orchestration du flux d'inscription
- Hash des mots de passe
- Génération et signature des tokens
- Vérification email
- Logique métier de l'authentification

Ne fait PAS :
- Accès direct à la base de données (délégué au repository)
- Envoi d'emails (délégué à EmailService)
- Validation des entrées HTTP (délégué au contrôleur)
"""

import asyncio
import bcrypt
from typing import Optional, Tuple
from secrets import token_urlsafe
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from model.user import User

# from passlib.hash import bcrypt
from dataclasses import dataclass
import logging

from repositories.user_repository import UserRepository
from domain.email_service import EmailService
from app.settings import Settings


logger = logging.getLogger(__name__)


class UserService:
    def __init__(
        self, settings: Settings, user_repo: UserRepository, email_service: EmailService
    ):
        self.settings = settings
        self.user_repo = user_repo
        self.email_service = email_service

    async def create_user(self, username: str, email: str, password: str):
        """
        Inscrire un nouvel utilisateur avec vérification email

        Flux complet :
        1. Vérifier que l'email n'existe pas déjà
        2. Hasher le mot de passe
        3. Créer l'utilisateur (is_active=False)
        4. Générer un token aléatoire
        5. Enregistrer le token en base
        6. Signer le token avec itsdangerous
        7. Envoyer l'email avec le lien de vérification

        Args:
            email: Email de l'utilisateur
            password: Mot de passe en clair (sera hashé)
            first_name: Prénom (optionnel)
            last_name: Nom (optionnel)

        Returns:
            Tuple (User créé, booléen indiquant si l'email a été envoyé)

        Raises:
            ValueError: Si l'email existe déjà
            Exception: Pour les autres erreurs
        """

        try:
            # Étape 1 : Vérifier l'unicité de l'email
            if await self.user_repo.user_exists(email):
                raise ValueError(f"Un utilisateur avec l'email {email} existe déjà")

            # Étape 2 : Hasher le mot de passe avec bcrypt
            hashed_password = await self._async_hash_password(password)

            # Étape 3 : Créer l'utilisateur (inactif par défaut)
            user = await self.user_repo.create_user(
                email=email,
                username=username,
                hashed_password=hashed_password,
                is_active=False,  # Sera activé après vérification email
            )

            logger.info(f"User registered: id={user.id}, email={email}")

            # Étape 4 : Générer un token aléatoire cryptographiquement sûr
            raw_token = self._generate_token()

            # Étape 5 : Enregistrer le token en base de données
            await self.user_repo.create_verification_token(
                user_id=user.id,
                token=raw_token,
                expiry_delay=self.settings.verification.token_expiry_delay,
            )

            # Étape 6 : Signer le token (user_id + token)
            signed_token = self._sign_token(user.id, raw_token)

            # Étape 7 : Construire l'URL et envoyer l'email
            verification_url = f"{self.settings.verification.base_url}/users/verify-email/{signed_token}"
            email_sent = await self.email_service.send_verification_email(
                to=user.email, verification_link=verification_url, username=username
            )
            if not email_sent:
                logger.warning(f"Failed to send verification email to {email}")
                logger.info(
                    "Development hint: use this verification link to activate the account: %s",
                    verification_url,
                )

            # retourne l'utilisateur crée
            return user, email_sent

        except ValueError:
            # Propager les erreurs de validation
            raise
        except Exception as e:
            # Logger et propager les autres erreurs
            logger.error(f"Registration failed for {email}: {str(e)}")
            raise

    def _hash_password(self, password: str) -> str:
        """
        Hasher un mot de passe avec bcrypt
        Returns: Hash bcrypt (format: $2b$12$...)
        """
        return bcrypt.hashpw(password=password, salt=bcrypt.gensalt()).decode("utf-8")

    async def _async_hash_password(self, password: str) -> str:
        """Hash un mot de passe de manière sécurisée"""
        password_bytes = password.encode("utf-8")
        hashed = await asyncio.to_thread(
            bcrypt.hashpw, password_bytes, bcrypt.gensalt()
        )
        return hashed.decode("utf-8")

    async def verify_password(self, password: str, hashed_password: str) -> bool:
        """Vérifie si le mot de passe correspond au hash"""
        password_bytes = password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return await asyncio.to_thread(bcrypt.checkpw, password_bytes, hashed_bytes)

    def _generate_token(self) -> str:
        """
        Returns: Token aléatoire (ex: "Xy7_AbC123...")
        """
        return token_urlsafe(32)

    def _sign_token(self, user_id: int, token: str) -> str:
        """
        Signer un token avec itsdangerous
        Returns: Token signé et encodé (ex: "eyJh...signature")
        """
        serializer = URLSafeTimedSerializer(self.settings.verification.secret)
        return serializer.dumps([user_id, token])

    async def verify_email(self, signed_token: str) -> Tuple[bool, str, Optional[User]]:
        """
        Vérifier l'email d'un utilisateur

        Flux complet :
        1. Désigner le token signé (logique métier dans le service)
        2. Appeler le repository pour récupérer le token
        3. Vérifier la validité du token
        4. Activer l'utilisateur
        """
        try:
            logger.info(
                f"Starting email verification for token: {signed_token[:20]}..."
            )

            # ÉTAPE 1 : Désigner le token (LOGIQUE MÉTIER dans le service)
            serializer = URLSafeTimedSerializer(self.settings.verification.secret)

            try:
                # Désignation du token signé
                user_id, raw_token = serializer.loads(
                    signed_token,
                    max_age=self.settings.verification.token_expiry_delay * 3600,
                )
                logger.info(f"Token deserialized successfully: user_id={user_id}")
            except SignatureExpired:
                logger.warning(f"Verification token expired")
                try:
                    user_id, raw_token = serializer.loads_unsafe(signed_token)
                    user = await self.user_repo.get_user_by_id(user_id)
                    return (
                        False,
                        "expired",
                        user,
                    )  # ← Retourne "expired" + user pour récupérer l'email
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

            # ÉTAPE 2 : Récupérer le token en base (via repository)
            logger.info(f"Looking for token in database: user_id={user_id}")
            token = await self.user_repo.get_verification_token(
                user_id, raw_token, only_valid=True
            )

            if not token:
                logger.warning(
                    f"Token not found or already used: user_id={user_id}, raw_token={raw_token[:10]}..."
                )
                user = await self.user_repo.get_user_by_id(user_id)

                # Si l'utilisateur existe et est actif, c'est que le token a déjà été utilisé
                if user and user.is_active:
                    return False, "already_active", user
                return False, "Ce lien de vérification n'est plus valide.", None

            logger.info(f"Token found in database: token_id={token.id}")

            # ÉTAPE 3 : Récupérer l'utilisateur
            user = await self.user_repo.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: user_id={user_id}")
                return False, "Utilisateur introuvable.", None

            logger.info(f"User found: user_id={user.id}, is_active={user.is_active}")

            # ÉTAPE 4 : Vérifier si déjà actif
            if user.is_active:
                logger.info(f"User already active: user_id={user_id}")
                await self.user_repo.mark_token_as_used(token.id)
                await self.user_repo.delete_user_tokens(user_id)
                return True, "already_active", user

            # ÉTAPE 5 : Marquer le token comme utilisé
            logger.info(f"Marking token as used: token_id={token.id}")
            await self.user_repo.mark_token_as_used(token.id)

            # ÉTAPE 6 : Supprimer tous les autres tokens
            logger.info(f"Deleting other tokens for user: user_id={user_id}")
            await self.user_repo.delete_user_tokens(user_id)

            # ÉTAPE 7 : Activer l'utilisateur
            logger.info(f"Activating user: user_id={user_id}")
            activated_user = await self.user_repo.activate_user(user_id)

            if not activated_user:
                logger.error(f"Failed to activate user: user_id={user_id}")
                return False, "Erreur lors de l'activation du compte.", None

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
        """
        # Récupérer l'utilisateur
        user = await self.user_repo.get_user_by_email(email)

        if not user:
            raise ValueError("Aucun utilisateur trouvé avec cet email")

        if user.is_active:
            raise ValueError("Ce compte est déjà activé")

        # Supprimer les anciens tokens
        await self.user_repo.delete_user_tokens(user.id)

        # Générer un nouveau token
        raw_token = self._generate_token()

        # Enregistrer le nouveau token
        await self.user_repo.create_verification_token(
            user_id=user.id,
            token=raw_token,
            expiry_delay=self.settings.verification.token_expiry_delay,
        )

        # Signer le token
        signed_token = self._sign_token(user.id, raw_token)

        # Envoyer l'email
        verification_url = (
            f"{self.settings.verification.base_url}/users/verify-email/{signed_token}"
        )

        email_sent = await self.email_service.send_resend_verification_email(
            to=user.email, verification_link=verification_url, username=user.username
        )

        logger.info(f"Verification email resent to: {email}")

        return email_sent

    async def authenticate_user(self, identifier: str, password: str) -> Optional[User]:
        """
        Authentifier un utilisateur avec email/username et mot de passe

        Args:
            identifier: Email ou username de l'utilisateur
            password: Mot de passe en clair

        Returns:
            User si authentification réussie, None sinon

        Raises:
            ValueError: Si le compte n'est pas activé
        """
        try:
            # Essayer de récupérer l'utilisateur par email ou username
            user = await self.user_repo.get_user_by_email(identifier)

            # Si pas trouvé par email, essayer par username
            if not user:
                user = await self.user_repo.get_user_by_username(identifier)

            if not user:
                logger.warning(
                    f"Authentication failed: user not found for identifier={identifier}"
                )
                return None

            # Vérifier si le compte est activé
            if not user.is_active:
                logger.warning(
                    f"Authentication failed: account not activated for user_id={user.id}"
                )
                raise ValueError(
                    "Votre compte n'est pas encore activé. Veuillez vérifier votre email."
                )

            # Vérifier le mot de passe
            is_valid = await self.verify_password(password, user.password)

            if not is_valid:
                logger.warning(
                    f"Authentication failed: invalid password for user_id={user.id}"
                )
                return None

            logger.info(
                f"User authenticated successfully: user_id={user.id}, email={user.email}"
            )
            return user

        except ValueError:
            # Propager les erreurs de validation (compte non activé)
            raise
        except Exception as e:
            logger.error(f"Authentication error for identifier={identifier}: {str(e)}")
            return None

    # ==========================================
    # RÉINITIALISATION DE MOT DE PASSE
    # ==========================================

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
                expiry_hours=self.settings.verification.token_expiry_delay,  # Token valide 1 heure
            )

            # 5. Signer le token
            signed_token = self._sign_token(user.id, raw_token)

            # 6. Construire l'URL et envoyer l'email
            reset_url = f"{self.settings.verification.base_url}/users/reset-password/{signed_token}"

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
                logger.warning(f"Password reset token not found or already used")
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
