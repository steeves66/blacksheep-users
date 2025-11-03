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
            # ÉTAPE 1 : Désigner le token (LOGIQUE MÉTIER dans le service)
            serializer = URLSafeTimedSerializer(self.settings.verification.secret)

            try:
                # Désignation du token signé
                user_id, raw_token = serializer.loads(
                    signed_token,
                    max_age=self.settings.verification.token_expiry_delay * 3600,
                )
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
                except:
                    return (
                        False,
                        "Le lien de vérification a expiré. Veuillez demander un nouveau lien.",
                        None,
                    )
            except BadSignature:
                logger.warning(f"Invalid verification token signature")
                return False, "Le lien de vérification est invalide.", None

            # ÉTAPE 2 : Récupérer le token en base (via repository)
            token = await self.user_repo.get_verification_token(
                user_id, raw_token, only_valid=True
            )

            if not token:
                logger.warning(f"Token not found or already used: user_id={user_id}")
                user = await self.user_repo.get_user_by_id(user_id)

                # Si l'utilisateur existe et est actif, c'est que le token a déjà été utilisé
                if user and user.is_active:
                    return False, "already_active", user
                return False, "Ce lien de vérification n'est plus valide.", None

            # ÉTAPE 3 : Récupérer l'utilisateur
            user = await self.user_repo.get_user_by_id(user_id)
            if not user:
                logger.error(f"User not found: user_id={user_id}")
                return False, "Utilisateur introuvable.", None

            # ÉTAPE 4 : Vérifier si déjà actif
            if user.is_active:
                await self.user_repo.mark_token_as_used(token.id)
                await self.user_repo.delete_user_tokens(user_id)
                return True, "already_active", user

            # ÉTAPE 5 : Marquer le token comme utilisé
            await self.user_repo.mark_token_as_used(token.id)

            # ÉTAPE 6 : Supprimer tous les autres tokens
            await self.user_repo.delete_user_tokens(user_id)

            # ÉTAPE 7 : Activer l'utilisateur
            activated_user = await self.user_repo.activate_user(user_id)

            if not activated_user:
                logger.error(f"Failed to activate user: user_id={user_id}")
                return False, "Erreur lors de l'activation du compte.", None

            logger.info(
                f"User email verified and activated: user_id={user_id}, email={user.email}"
            )
            return True, "Votre compte a été activé avec succès !", activated_user

        except Exception as e:
            logger.error(f"Error during email verification: {e}")
            return False, "Une erreur s'est produite lors de la vérification.", None

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
