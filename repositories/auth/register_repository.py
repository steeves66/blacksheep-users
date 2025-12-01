"""
RegisterRepository - Repository pour l'inscription simple

Responsabilités :
- Accès à la base de données pour l'inscription simple
- Vérification de l'existence des utilisateurs
- Création d'utilisateurs actifs

Ne fait PAS :
- Logique métier (délégué au service)
- Hash des mots de passe (délégué au service)
"""

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from model.user import User

logger = logging.getLogger(__name__)


class RegisterRepository:
    """Repository pour l'inscription simple (sans vérification email)"""

    def __init__(self, db: AsyncSession):
        self.db = db

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
        self, email: str, username: str, hashed_password: str, is_active: bool = True
    ) -> User:
        """
        Créer un nouvel utilisateur

        Args:
            email: Email de l'utilisateur
            username: Nom d'utilisateur
            hashed_password: Mot de passe déjà hashé
            is_active: État actif (True par défaut pour inscription simple)

        Returns:
            User créé

        Raises:
            Exception si erreur lors de la création
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

        logger.info(f"User created in database: id={user.id}, email={email}")
        return user

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
