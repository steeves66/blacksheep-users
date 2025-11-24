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
import logging

# from passlib.hash import bcrypt
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from secrets import token_urlsafe
from typing import Any, Dict, List, Optional, Tuple

import bcrypt
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.settings import Settings
from domain.email_service import EmailService
from model.user import Permission, Role, User
from repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)


class UserService:
    def __init__(
        self, settings: Settings, user_repo: UserRepository, email_service: EmailService
    ):
        self.settings = settings
        self.user_repo = user_repo
        self.email_service = email_service

    async def create_simple_user(self, username: str, email: str, password: str):
        """Créer un utilisateur simple sans vérification email"""

        try:
            # Hasher le mot de passe
            hashed_password = await self._async_hash_password(password)

            # Créer l'utilisateur (actif immédiatement)
            user = await self.user_repo.create_user(
                email=email,
                username=username,
                hashed_password=hashed_password,
                is_active=True,
            )

            logger.info(f"Simple user created: id={user.id}, email={email}")
            return user

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error creating simple user: {e}", exc_info=True)
            raise

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

    # ==========================================
    # GESTION DES RÔLES
    # ==========================================
    async def create_role(
        self,
        name: str,
        display_name: str,
        description: Optional[str] = None,
        priority: int = 0,
    ) -> Role:
        """
        Créer un nouveau rôle avec validation

        Validations :
        - Le nom ne doit pas contenir d'espaces
        - Le nom doit être en minuscules
        - Le nom doit être unique
        """
        # Validation
        if " " in name:
            raise ValueError("Le nom du rôle ne doit pas contenir d'espaces")

        if name != name.lower():
            raise ValueError("Le nom du rôle doit être en minuscules")

        # Vérifier l'unicité
        existing = await self.user_repo.get_role_by_name(name)
        if existing:
            raise ValueError(f"Un rôle avec le nom '{name}' existe déjà")

        return await self.user_repo.create_role(
            name=name,
            display_name=display_name,
            description=description,
            priority=priority,
        )

    async def assign_permissions_to_role(
        self, role_id: int, permission_names: List[str]
    ) -> Dict[str, Any]:
        """
        Assigner plusieurs permissions à un rôle

        Returns:
            Dict avec statistiques (success_count, failed_count, failures)
        """
        success_count = 0
        failed_count = 0
        failures = []

        for perm_name in permission_names:
            permission = await self.user_repo.get_permission_by_name(perm_name)

            if not permission:
                failed_count += 1
                failures.append(
                    {"permission": perm_name, "reason": "Permission not found"}
                )
                continue

            success = await self.user_repo.assign_permission_to_role(
                role_id, permission.id
            )

            if success:
                success_count += 1
            else:
                failed_count += 1
                failures.append(
                    {"permission": perm_name, "reason": "Assignment failed"}
                )

        logger.info(
            f"Permissions assigned to role {role_id}: "
            f"success={success_count}, failed={failed_count}"
        )

        return {
            "success_count": success_count,
            "failed_count": failed_count,
            "failures": failures,
        }

    # ==========================================
    # GESTION DES PERMISSIONS
    # ==========================================

    async def create_permission(
        self,
        name: str,
        display_name: str,
        resource: str,
        action: str,
        description: Optional[str] = None,
    ) -> Permission:
        """
        Créer une nouvelle permission avec validation

        Validations :
        - Format : resource.action
        - Nom en minuscules
        - Unique
        """
        # Validation du format
        expected_name = f"{resource}.{action}"
        if name != expected_name:
            raise ValueError(
                f"Le nom doit suivre le format 'resource.action'. "
                f"Attendu: '{expected_name}', reçu: '{name}'"
            )

        if name != name.lower():
            raise ValueError("Le nom de la permission doit être en minuscules")

        # Vérifier l'unicité
        existing = await self.user_repo.get_permission_by_name(name)
        if existing:
            raise ValueError(f"Une permission avec le nom '{name}' existe déjà")

        return await self.user_repo.create_permission(
            name=name,
            display_name=display_name,
            resource=resource,
            action=action,
            description=description,
        )

    async def get_permissions_by_resource(self, resource: str) -> List[Permission]:
        """Récupérer toutes les permissions d'une ressource"""
        return await self.user_repo.get_permissions_by_resource(resource)

    # ==========================================
    # GESTION UTILISATEURS <-> RÔLES
    # ==========================================

    async def assign_role_to_user(
        self, user_id: int, role_name: str, assigned_by: Optional[int] = None
    ) -> bool:
        """
        Assigner un rôle à un utilisateur par nom de rôle

        Args:
            user_id: ID de l'utilisateur
            role_name: Nom du rôle
            assigned_by: ID de l'utilisateur qui effectue l'attribution
        """
        role = await self.user_repo.get_role_by_name(role_name)

        if not role:
            raise ValueError(f"Rôle '{role_name}' introuvable")

        return await self.user_repo.assign_role_to_user(user_id, role.id, assigned_by)

    async def assign_multiple_roles_to_user(
        self, user_id: int, role_names: List[str], assigned_by: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Assigner plusieurs rôles à un utilisateur

        Returns:
            Dict avec statistiques
        """
        success_count = 0
        failed_count = 0
        failures = []

        for role_name in role_names:
            try:
                success = await self.assign_role_to_user(
                    user_id, role_name, assigned_by
                )
                if success:
                    success_count += 1
                else:
                    failed_count += 1
                    failures.append({"role": role_name, "reason": "Assignment failed"})
            except ValueError as e:
                failed_count += 1
                failures.append({"role": role_name, "reason": str(e)})

        logger.info(
            f"Roles assigned to user {user_id}: "
            f"success={success_count}, failed={failed_count}"
        )

        return {
            "success_count": success_count,
            "failed_count": failed_count,
            "failures": failures,
        }

    async def remove_role_from_user(self, user_id: int, role_name: str) -> bool:
        """Retirer un rôle d'un utilisateur"""
        role = await self.user_repo.get_role_by_name(role_name)

        if not role:
            raise ValueError(f"Rôle '{role_name}' introuvable")

        return await self.user_repo.remove_role_from_user(user_id, role.id)

    async def get_user_roles(self, user_id: int) -> List[Role]:
        """Récupérer tous les rôles d'un utilisateur"""
        return await self.user_repo.get_user_roles(user_id)

    # ==========================================
    # ⭐ GESTION PERMISSIONS DIRECTES
    # ==========================================

    async def grant_permission_to_user(
        self,
        user_id: int,
        permission_name: str,
        assigned_by: Optional[int] = None,
        duration_hours: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Accorder une permission directe à un utilisateur

        Args:
            user_id: ID de l'utilisateur
            permission_name: Nom de la permission (ex: 'user.delete')
            assigned_by: ID de l'utilisateur qui accorde la permission
            duration_hours: Durée de validité en heures (None = permanente)
            reason: Raison de l'attribution (pour audit)

        Returns:
            bool: True si succès

        Example:
            # Permission permanente
            await service.grant_permission_to_user(
                user_id=123,
                permission_name='post.publish',
                assigned_by=1,
                reason='Auteur invité pour événement spécial'
            )

            # Permission temporaire (24h)
            await service.grant_permission_to_user(
                user_id=456,
                permission_name='user.ban',
                assigned_by=1,
                duration_hours=24,
                reason='Modération temporaire pendant événement'
            )
        """
        permission = await self.user_repo.get_permission_by_name(permission_name)

        if not permission:
            raise ValueError(f"Permission '{permission_name}' introuvable")

        # Calculer la date d'expiration si durée spécifiée
        expires_at = None
        if duration_hours:
            expires_at = datetime.now(timezone.utc) + timedelta(hours=duration_hours)

        success = await self.user_repo.assign_permission_to_user(
            user_id=user_id,
            permission_id=permission.id,
            assigned_by=assigned_by,
            expires_at=expires_at,
            reason=reason,
        )

        if success:
            logger.info(
                f"Permission granted: user_id={user_id}, permission={permission_name}, "
                f"duration={duration_hours}h, reason={reason}"
            )

        return success

    async def revoke_permission_from_user(
        self, user_id: int, permission_name: str
    ) -> bool:
        """
        Révoquer une permission directe d'un utilisateur

        Note : Ne révoque pas les permissions héritées des rôles
        """
        permission = await self.user_repo.get_permission_by_name(permission_name)

        if not permission:
            raise ValueError(f"Permission '{permission_name}' introuvable")

        success = await self.user_repo.remove_permission_from_user(
            user_id, permission.id
        )

        if success:
            logger.info(
                f"Permission revoked: user_id={user_id}, permission={permission_name}"
            )

        return success

    async def grant_multiple_permissions_to_user(
        self,
        user_id: int,
        permission_names: List[str],
        assigned_by: Optional[int] = None,
        duration_hours: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Accorder plusieurs permissions directes à un utilisateur

        Returns:
            Dict avec statistiques
        """
        success_count = 0
        failed_count = 0
        failures = []

        for perm_name in permission_names:
            try:
                success = await self.grant_permission_to_user(
                    user_id=user_id,
                    permission_name=perm_name,
                    assigned_by=assigned_by,
                    duration_hours=duration_hours,
                    reason=reason,
                )
                if success:
                    success_count += 1
                else:
                    failed_count += 1
                    failures.append({"permission": perm_name, "reason": "Grant failed"})
            except ValueError as e:
                failed_count += 1
                failures.append({"permission": perm_name, "reason": str(e)})

        logger.info(
            f"Permissions granted to user {user_id}: "
            f"success={success_count}, failed={failed_count}"
        )

        return {
            "success_count": success_count,
            "failed_count": failed_count,
            "failures": failures,
        }

    async def get_user_direct_permissions(self, user_id: int) -> List[Permission]:
        """Récupérer uniquement les permissions directes (sans les rôles)"""
        return await self.user_repo.get_user_direct_permissions(user_id)

    async def get_user_direct_permissions_detailed(
        self, user_id: int
    ) -> List[Dict[str, Any]]:
        """
        Récupérer les permissions directes avec détails

        Returns:
            Liste de dicts contenant : permission, assigned_at, expires_at, reason, etc.
        """
        perms_with_details = (
            await self.user_repo.get_user_direct_permissions_with_details(user_id)
        )

        result = []
        for perm, details in perms_with_details:
            # Calculer si la permission est expirée ou expire bientôt
            is_expired = False
            expires_soon = False

            if details["expires_at"]:
                now = datetime.now(timezone.utc)
                is_expired = details["expires_at"] < now

                # Expire dans moins de 24h ?
                if not is_expired:
                    time_left = details["expires_at"] - now
                    expires_soon = time_left < timedelta(hours=24)

            result.append(
                {
                    "permission": perm,
                    "assigned_at": details["assigned_at"],
                    "assigned_by": details["assigned_by"],
                    "expires_at": details["expires_at"],
                    "reason": details["reason"],
                    "is_expired": is_expired,
                    "expires_soon": expires_soon,
                }
            )

        return result

    # ==========================================
    # VÉRIFICATIONS ET REQUÊTES
    # ==========================================

    async def user_has_permission(self, user_id: int, permission_name: str) -> bool:
        """
        Vérifier si un utilisateur a une permission (directe ou via rôle)
        """
        return await self.user_repo.user_has_permission(user_id, permission_name)

    async def user_has_role(self, user_id: int, role_name: str) -> bool:
        """Vérifier si un utilisateur a un rôle"""
        return await self.user_repo.user_has_role(user_id, role_name)

    async def get_user_all_permissions(self, user_id: int) -> Dict[str, Any]:
        """
        Récupérer toutes les permissions d'un utilisateur avec détails

        Returns:
            Dict avec :
            - all_permissions : Liste complète (dédupliquée)
            - direct_permissions : Permissions directes uniquement
            - role_permissions : Permissions via rôles
        """
        all_perms = await self.user_repo.get_user_all_permissions(user_id)
        direct_perms = await self.user_repo.get_user_direct_permissions(user_id)
        roles = await self.user_repo.get_user_roles(user_id)

        role_perms_set = set()
        for role in roles:
            role_perms = await self.user_repo.get_role_permissions(role.id)
            for perm in role_perms:
                role_perms_set.add(perm.name)

        return {
            "all_permissions": all_perms,
            "direct_permissions": [p.name for p in direct_perms],
            "role_permissions": sorted(list(role_perms_set)),
        }

    async def get_user_summary(self, user_id: int) -> Dict[str, Any]:
        """
        Récupérer un résumé complet RBAC pour un utilisateur

        Returns:
            Dict avec rôles, permissions, statistiques
        """
        roles = await self.get_user_roles(user_id)
        perms_details = await self.get_user_all_permissions(user_id)
        direct_perms_detailed = await self.get_user_direct_permissions_detailed(user_id)

        # Compter les permissions expirées/expires bientôt
        expired_count = sum(1 for p in direct_perms_detailed if p["is_expired"])
        expires_soon_count = sum(1 for p in direct_perms_detailed if p["expires_soon"])

        return {
            "roles": [
                {
                    "id": role.id,
                    "name": role.name,
                    "display_name": role.display_name,
                    "priority": role.priority,
                }
                for role in roles
            ],
            "permissions": perms_details,
            "direct_permissions_detailed": direct_perms_detailed,
            "statistics": {
                "total_roles": len(roles),
                "total_permissions": len(perms_details["all_permissions"]),
                "direct_permissions_count": len(perms_details["direct_permissions"]),
                "role_permissions_count": len(perms_details["role_permissions"]),
                "expired_permissions": expired_count,
                "expires_soon_permissions": expires_soon_count,
            },
        }

    # ==========================================
    # MAINTENANCE
    # ==========================================

    async def cleanup_expired_permissions(self) -> int:
        """
        Nettoyer les permissions directes expirées

        À exécuter régulièrement (CRON job)
        """
        count = await self.user_repo.cleanup_expired_permissions()
        logger.info(f"Cleaned up {count} expired direct permissions")
        return count

    async def get_system_statistics(self) -> Dict[str, Any]:
        """
        Récupérer les statistiques globales du système RBAC

        Returns:
            Dict avec statistiques complètes
        """
        all_roles = await self.user_repo.get_all_roles()
        all_permissions = await self.user_repo.get_all_permissions()

        # Compter les utilisateurs par rôle
        role_stats = []
        for role in all_roles:
            user_count = await self.user_repo.get_role_user_count(role.id)
            role_stats.append(
                {
                    "role": role.name,
                    "display_name": role.display_name,
                    "user_count": user_count,
                    "priority": role.priority,
                }
            )

        # Compter les utilisateurs avec permissions directes
        permission_stats = []
        for perm in all_permissions:
            direct_user_count = await self.user_repo.get_permission_direct_user_count(
                perm.id
            )
            role_count = await self.user_repo.get_permission_role_count(perm.id)

            if direct_user_count > 0:  # Seulement si utilisé directement
                permission_stats.append(
                    {
                        "permission": perm.name,
                        "direct_user_count": direct_user_count,
                        "role_count": role_count,
                    }
                )

        return {
            "total_roles": len(all_roles),
            "total_permissions": len(all_permissions),
            "role_statistics": sorted(
                role_stats, key=lambda x: x["user_count"], reverse=True
            ),
            "permission_statistics": sorted(
                permission_stats, key=lambda x: x["direct_user_count"], reverse=True
            ),
        }
