"""
ResetPasswordRepository - Repository pour la réinitialisation du mot de passe

Responsabilités :
- Accès à la base de données pour la réinitialisation du mot de passe
- Gestion des tokens de réinitialisation
- Mise à jour du mot de passe
- Récupération des utilisateurs

Ne fait PAS :
- Logique métier (délégué au service)
- Génération/signature des tokens (délégué au service)
- Hash des mots de passe (délégué au service)
- Envoi d'emails (délégué au service)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from model.user import PasswordResetToken, User

logger = logging.getLogger(__name__)


class ResetPasswordRepository:
    """Repository pour la réinitialisation du mot de passe"""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ==========================================
    # GESTION DES UTILISATEURS
    # ==========================================

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Récupérer un utilisateur par email

        Args:
            email: Email de l'utilisateur

        Returns:
            User si trouvé, None sinon
        """
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Récupérer un utilisateur par ID

        Args:
            user_id: ID de l'utilisateur

        Returns:
            User si trouvé, None sinon
        """
        result = await self.db.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def update_user_password(
        self, user_id: int, hashed_password: str
    ) -> Optional[User]:
        """
        Mettre à jour le mot de passe d'un utilisateur

        Args:
            user_id: ID de l'utilisateur
            hashed_password: Nouveau mot de passe hashé

        Returns:
            User mis à jour si trouvé, None sinon
        """
        user = await self.get_user_by_id(user_id)
        if user:
            user.password = hashed_password
            await self.db.commit()
            await self.db.refresh(user)
            logger.info(f"Password updated for user_id={user_id}")
        return user

    # ==========================================
    # GESTION DES TOKENS DE RÉINITIALISATION
    # ==========================================

    async def create_password_reset_token(
        self, user_id: int, token: str, expiry_hours: int
    ) -> PasswordResetToken:
        """
        Créer un token de réinitialisation de mot de passe

        Args:
            user_id: ID de l'utilisateur
            token: Token non signé
            expiry_hours: Durée de validité en heures

        Returns:
            PasswordResetToken créé
        """
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

        reset_token = PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
        )

        self.db.add(reset_token)
        await self.db.commit()
        await self.db.refresh(reset_token)

        logger.info(
            f"Password reset token created: user_id={user_id}, expires_at={expires_at}"
        )
        return reset_token

    async def get_password_reset_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[PasswordResetToken]:
        """
        Récupérer un token de réinitialisation

        Args:
            user_id: ID de l'utilisateur
            token: Token non signé
            only_valid: Ne récupérer que les tokens valides (non utilisés, non expirés)

        Returns:
            PasswordResetToken si trouvé, None sinon
        """
        query = select(PasswordResetToken).where(
            PasswordResetToken.user_id == user_id, PasswordResetToken.token == token
        )

        if only_valid:
            query = query.where(
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > datetime.now(timezone.utc),
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_password_reset_token_as_used(self, token_id: int) -> None:
        """
        Marquer un token de réinitialisation comme utilisé

        Args:
            token_id: ID du token
        """
        result = await self.db.execute(
            select(PasswordResetToken).where(PasswordResetToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if token:
            token.used_at = datetime.now(timezone.utc)
            await self.db.commit()
            logger.info(f"Password reset token marked as used: token_id={token_id}")

    async def delete_user_password_reset_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens de réinitialisation d'un utilisateur

        Args:
            user_id: ID de l'utilisateur

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        )
        tokens = result.scalars().all()

        for token in tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(
            f"Deleted {len(tokens)} password reset tokens for user_id={user_id}"
        )
        return len(tokens)
