"""
UserRepository - Couche d'accès aux données

Centralise toutes les opérations sur la base de données :
- CRUD utilisateurs
- CRUD tokens de vérification
- Opérations utilitaires (nettoyage, activation, etc.)

Avantages :
- Découplage : le service n'a pas de dépendance SQLAlchemy directe
- Testabilité : facile de mocker ce repository dans les tests
- Réutilisabilité : ces méthodes peuvent être utilisées par plusieurs services
- Maintenance : changement de DB sans toucher aux services
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, select, delete, func
import logging

from app.settings import Settings
from model.user import User, EmailVerificationToken, PasswordResetToken


logger = logging.getLogger(__name__)


class UserRepository:
    """Repository pour gérer les utilisateurs et tokens de vérification"""

    def __init__(self, db: AsyncSession, settings: Settings):
        """
        Initialise le repository avec une session de base de données

        Args:
            db: Session SQLAlchemy active
        """
        self.db = db
        self.settings = settings

    # ==========================================
    # OPÉRATIONS SUR LES UTILISATEURS
    # ==========================================

    async def create_user(
        self,
        email: str,
        username: str,
        hashed_password: str,
        is_active: bool = False,
    ) -> User:
        """
        Créer un nouvel utilisateur

        Note : Le mot de passe doit déjà être hashé avant l'appel

        Args:
            email: Email unique de l'utilisateur
            hashed_password: Mot de passe déjà hashé (bcrypt)
            first_name: Prénom (optionnel)
            last_name: Nom (optionnel)
            is_active: Statut initial (False pour inscription avec email)

        Returns:
            Instance User créée et persistée
        """
        user = User(
            email=email,
            username=username,
            password=hashed_password,
            is_active=is_active,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)  # Récupère l'ID auto-généré

        logger.info(f"User created: id={user.id}, email={email}, is_active={is_active}")
        return user

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Récupérer un utilisateur par son ID
        """
        result = await self.db.execute(select(User).filter(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Récupérer un utilisateur par son email
        """
        result = await self.db.execute(select(User).filter(User.email == email))
        return result.scalar_one_or_none()

    async def user_exists(self, email: str) -> bool:
        """
        Vérifier si un utilisateur avec cet email existe déjà
        """
        result = await self.db.execute(
            select(func.count()).select_from(User).filter(User.email == email)
        )
        count = result.scalar()
        return count > 0

    async def activate_user(self, user_id: int) -> Optional[User]:
        """
        Activer le compte d'un utilisateur
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot activate user: user_id={user_id} not found")
            return None

        user.is_active = True
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"User activated: id={user.id}, email={user.email}")
        return user

    async def deactivate_user(self, user_id: int) -> Optional[User]:
        """
        Désactiver le compte d'un utilisateur
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot deactivate user: user_id={user_id} not found")
            return None

        user.is_active = False
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"User deactivated: id={user.id}, email={user.email}")
        return user

    async def delete_user(self, user_id: int) -> bool:
        """
        Supprimer un utilisateur (hard delete)
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            return False

        await self.db.delete(user)
        await self.db.commit()

        logger.info(f"User deleted: id={user_id}")
        return True

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Récupérer un utilisateur par son nom d'utilisateur
        """
        result = await self.db.execute(select(User).filter(User.username == username))
        return result.scalar_one_or_none()

    # ============================================================
    # OPÉRATIONS SUR LES TOKENS DE REGISTER WITH EMAILVÉRIFICATION
    # ============================================================

    async def create_verification_token(
        self, user_id: int, token: str, expiry_delay: int = 24
    ) -> EmailVerificationToken:
        """
        Créer un token de vérification pour un utilisateur

        Args:
            user_id: ID de l'utilisateur
            token: Token aléatoire généré (secrets.token_urlsafe)
            expiry_hours: Nombre d'heures avant expiration (défaut: 24h)

        Returns:
            Instance EmailVerificationToken créée
        """
        # Calculer la date d'expiration
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=self.settings.verification.token_expiry_delay
        )

        token_record = EmailVerificationToken(
            user_id=user_id, token=token, expires_at=expires_at, is_used=False
        )

        self.db.add(token_record)
        await self.db.commit()
        await self.db.refresh(token_record)

        logger.info(
            f"Verification token created: user_id={user_id}, expires_at={expires_at}"
        )
        return token_record

    async def get_verification_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[EmailVerificationToken]:
        """
        Récupérer un token de vérification

        Args:
            user_id: ID de l'utilisateur
            token: Token à rechercher
            only_valid: Si True, ne retourne que les tokens valides (non utilisés, non expirés)

        Returns:
            EmailVerificationToken ou None si non trouvé
        """
        # Construire la requête de base
        query = select(EmailVerificationToken).filter(
            and_(
                EmailVerificationToken.user_id == user_id,
                EmailVerificationToken.token == token,
            )
        )

        # Filtrer pour ne garder que les tokens valides si demandé
        if only_valid:
            query = query.filter(
                and_(
                    EmailVerificationToken.is_used == False,
                    EmailVerificationToken.expires_at > datetime.now(timezone.utc),
                )
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_token_as_used(self, token_id: int) -> bool:
        """
        Marquer un token comme utilisé (empêche la réutilisation)
        """
        result = await self.db.execute(
            select(EmailVerificationToken).filter(EmailVerificationToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if not token:
            return False

        token.is_used = True
        await self.db.commit()

        logger.info(f"Token marked as used: id={token_id}, user_id={token.user_id}")
        return True

    async def delete_expired_tokens(self) -> int:
        """
        Supprimer tous les tokens expirés (tâche de nettoyage)

        À exécuter régulièrement (CRON job quotidien recommandé)

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            delete(EmailVerificationToken).filter(
                EmailVerificationToken.expires_at < datetime.now(timezone.utc)
            )
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} expired tokens")
        return count

    async def delete_user_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens d'un utilisateur

        Utilisé pour :
        - Renvoyer un nouvel email (supprimer les anciens tokens)
        - Nettoyage après activation

        Args:
            user_id: ID de l'utilisateur

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            delete(EmailVerificationToken).filter(
                EmailVerificationToken.user_id == user_id
            )
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} tokens for user_id={user_id}")
        return count

    # ==========================================
    # OPÉRATIONS SUR LES TOKENS DE RESET PASSWORD
    # ==========================================

    async def create_password_reset_token(
        self, user_id: int, token: str, expiry_hours: int = 1
    ) -> PasswordResetToken:
        """
        Créer un token de réinitialisation de mot de passe

        Args:
            user_id: ID de l'utilisateur
            token: Token aléatoire généré (secrets.token_urlsafe)
            expiry_hours: Nombre d'heures avant expiration (défaut: 1h)

        Returns:
            Instance PasswordResetToken créée
        """
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

        token_record = PasswordResetToken(
            user_id=user_id, token=token, expires_at=expires_at, is_used=False
        )

        self.db.add(token_record)
        await self.db.commit()
        await self.db.refresh(token_record)

        logger.info(
            f"Password reset token created: user_id={user_id}, expires_at={expires_at}"
        )
        return token_record

    async def get_password_reset_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[PasswordResetToken]:
        """
        Récupérer un token de réinitialisation de mot de passe

        Args:
            user_id: ID de l'utilisateur
            token: Token à rechercher
            only_valid: Si True, ne retourne que les tokens valides

        Returns:
            PasswordResetToken ou None
        """
        query = select(PasswordResetToken).filter(
            and_(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.token == token,
            )
        )

        if only_valid:
            query = query.filter(
                and_(
                    PasswordResetToken.is_used == False,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc),
                )
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_password_reset_token_as_used(self, token_id: int) -> bool:
        """Marquer un token de reset comme utilisé"""
        result = await self.db.execute(
            select(PasswordResetToken).filter(PasswordResetToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if not token:
            return False

        token.is_used = True
        await self.db.commit()

        logger.info(
            f"Password reset token marked as used: id={token_id}, user_id={token.user_id}"
        )
        return True

    async def delete_user_password_reset_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens de reset d'un utilisateur

        Utilisé pour:
        - Nettoyer avant de créer un nouveau token
        - Invalider tous les tokens après un reset réussi
        """
        result = await self.db.execute(
            delete(PasswordResetToken).filter(PasswordResetToken.user_id == user_id)
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} password reset tokens for user_id={user_id}")
        return count

    async def update_user_password(
        self, user_id: int, hashed_password: str
    ) -> Optional[User]:
        """
        Mettre à jour le mot de passe d'un utilisateur

        Args:
            user_id: ID de l'utilisateur
            hashed_password: Nouveau mot de passe hashé

        Returns:
            User mis à jour ou None
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot update password: user_id={user_id} not found")
            return None

        user.password = hashed_password
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"Password updated: user_id={user.id}")
        return user
