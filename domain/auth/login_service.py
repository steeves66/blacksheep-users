"""
LoginService - Service pour la connexion des utilisateurs

Responsabilités :
- Authentifier un utilisateur avec email/username et mot de passe
- Vérifier le mot de passe
- Vérifier que le compte est actif
- Logique métier de l'authentification

Ne fait PAS :
- Gestion de la session (délégué au contrôleur)
- Accès direct à la base de données (délégué au repository)
"""

import asyncio
import logging
from typing import Optional

import bcrypt

from model.user import User
from repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)


class LoginService:
    """Service pour l'authentification des utilisateurs"""

    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def authenticate_user(
        self, identifier: str, password: str
    ) -> Optional[User]:
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
            # Essayer de récupérer l'utilisateur par email
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
            logger.error(
                f"Authentication error for identifier={identifier}: {str(e)}",
                exc_info=True,
            )
            return None

    async def verify_password(self, password: str, hashed_password: str) -> bool:
        """
        Vérifie si le mot de passe correspond au hash

        Args:
            password: Mot de passe en clair
            hashed_password: Hash bcrypt du mot de passe

        Returns:
            True si le mot de passe est correct, False sinon
        """
        password_bytes = password.encode("utf-8")
        hashed_bytes = hashed_password.encode("utf-8")
        return await asyncio.to_thread(bcrypt.checkpw, password_bytes, hashed_bytes)
