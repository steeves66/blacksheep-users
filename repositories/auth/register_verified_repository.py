"""
RegisterVerifiedRepository - Repository pour l'inscription avec vérification email

Responsabilités :
- Accès à la base de données pour l'inscription avec vérification
- Gestion des tokens de vérification
- Activation des utilisateurs
- Vérification de l'existence des utilisateurs

Ne fait PAS :
- Logique métier (délégué au service)
- Génération/signature des tokens (délégué au service)
- Envoi d'emails (délégué au service)
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from model.user import User, EmailVerificationToken as VerificationToken

logger = logging.getLogger(__name__)


class RegisterVerifiedRepository:
    """Repository pour l'inscription avec vérification email"""

    def __init__(self, db: AsyncSession):
        self.db = db

    # ==========================================
    # GESTION DES UTILISATEURS
    # ==========================================

    async def user_exists(self, email: str) -> bool:
        """
        Vérifier si un utilisateur existe avec cet email

        Args:
            email: Email à vérifier

        Returns:
            True si l'utilisateur existe, False sinon
        """
        result = await self.db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        return user is not None

    async def create_user(
        self, email: str, username: str, hashed_password: str, is_active: bool = False
    ) -> User:
        """
        Créer un nouvel utilisateur

        Args:
            email: Email de l'utilisateur
            username: Nom d'utilisateur
            hashed_password: Mot de passe déjà hashé
            is_active: État actif (False par défaut pour vérification email)

        Returns:
            User créé
        """
        user = User(
            email=email,
            username=username,
            password=hashed_password,
            is_active=is_active,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        logger.info(
            f"User created in database: id={user.id}, email={email}, is_active={is_active}"
        )
        return user

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

    async def activate_user(self, user_id: int) -> Optional[User]:
        """
        Activer un utilisateur

        Args:
            user_id: ID de l'utilisateur à activer

        Returns:
            User activé si trouvé, None sinon
        """
        user = await self.get_user_by_id(user_id)
        if user:
            user.is_active = True
            await self.db.commit()
            await self.db.refresh(user)
            logger.info(f"User activated: user_id={user_id}")
        return user

    # ==========================================
    # GESTION DES TOKENS DE VÉRIFICATION
    # ==========================================

    async def create_verification_token(
        self, user_id: int, token: str, expiry_delay: int
    ) -> VerificationToken:
        """
        Créer un token de vérification

        Args:
            user_id: ID de l'utilisateur
            token: Token non signé
            expiry_delay: Délai d'expiration en heures

        Returns:
            VerificationToken créé
        """
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_delay)

        verification_token = VerificationToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at,
        )

        self.db.add(verification_token)
        await self.db.commit()
        await self.db.refresh(verification_token)

        logger.info(
            f"Verification token created: user_id={user_id}, expires_at={expires_at}"
        )
        return verification_token

    async def get_verification_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[VerificationToken]:
        """
        Récupérer un token de vérification

        Args:
            user_id: ID de l'utilisateur
            token: Token non signé
            only_valid: Ne récupérer que les tokens valides (non utilisés, non expirés)

        Returns:
            VerificationToken si trouvé, None sinon
        """
        query = select(VerificationToken).where(
            VerificationToken.user_id == user_id, VerificationToken.token == token
        )

        if only_valid:
            query = query.where(
                VerificationToken.used_at.is_(None),
                VerificationToken.expires_at > datetime.now(timezone.utc),
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_token_as_used(self, token_id: int) -> None:
        """
        Marquer un token comme utilisé

        Args:
            token_id: ID du token
        """
        result = await self.db.execute(
            select(VerificationToken).where(VerificationToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if token:
            token.used_at = datetime.now(timezone.utc)
            await self.db.commit()
            logger.info(f"Verification token marked as used: token_id={token_id}")

    async def delete_user_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens d'un utilisateur

        Args:
            user_id: ID de l'utilisateur

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            select(VerificationToken).where(VerificationToken.user_id == user_id)
        )
        tokens = result.scalars().all()

        for token in tokens:
            await self.db.delete(token)

        await self.db.commit()

        logger.info(f"Deleted {len(tokens)} verification tokens for user_id={user_id}")
        return len(tokens)
