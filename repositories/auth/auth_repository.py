"""
AuthRepository - Repository pour l'authentification (login/logout)

Responsabilités :
- Accès à la base de données pour l'authentification
- Récupération des utilisateurs pour validation des credentials
- Gestion des données d'authentification

Ne fait PAS :
- Logique métier (délégué au service)
- Vérification des mots de passe (délégué au service)
- Gestion de la session (délégué au contrôleur)
"""

import logging
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from model.user import User

logger = logging.getLogger(__name__)


class AuthRepository:
    """Repository pour l'authentification (login + logout)"""

    def __init__(self, db: AsyncSession):
        self.db = db

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

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Récupérer un utilisateur par nom d'utilisateur

        Args:
            username: Nom d'utilisateur

        Returns:
            User si trouvé, None sinon
        """
        result = await self.db.execute(select(User).where(User.username == username))
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
