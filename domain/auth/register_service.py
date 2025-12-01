"""
RegisterService - Service pour l'inscription simple sans vérification email

Responsabilités :
- Créer un utilisateur actif immédiatement
- Hasher le mot de passe
- Validation métier

Ne fait PAS :
- Envoi d'emails
- Vérification email
- Accès direct à la base de données (délégué au repository)
"""

import asyncio
import logging

import bcrypt

from repositories.user_repository import UserRepository

logger = logging.getLogger(__name__)


class RegisterService:
    """Service pour l'inscription simple (utilisateur actif immédiatement)"""

    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def create_simple_user(self, username: str, email: str, password: str):
        """
        Créer un utilisateur simple sans vérification email
        L'utilisateur est actif immédiatement

        Args:
            username: Nom d'utilisateur
            email: Email de l'utilisateur
            password: Mot de passe en clair (sera hashé)

        Returns:
            User créé

        Raises:
            ValueError: Si l'email existe déjà ou validation échoue
        """
        try:
            # Vérifier que l'email n'existe pas déjà
            if await self.user_repo.user_exists(email):
                raise ValueError(f"Un utilisateur avec l'email {email} existe déjà")

            # Hasher le mot de passe
            hashed_password = await self._async_hash_password(password)

            # Créer l'utilisateur (actif immédiatement)
            user = await self.user_repo.create_user(
                email=email,
                username=username,
                hashed_password=hashed_password,
                is_active=True,  # ✅ Actif immédiatement
            )

            logger.info(f"Simple user created: id={user.id}, email={email}")
            return user

        except ValueError:
            raise
        except Exception as e:
            logger.error(f"Error creating simple user: {e}", exc_info=True)
            raise

    async def _async_hash_password(self, password: str) -> str:
        """Hash un mot de passe de manière asynchrone"""
        password_bytes = password.encode("utf-8")
        hashed = await asyncio.to_thread(
            bcrypt.hashpw, password_bytes, bcrypt.gensalt()
        )
        return hashed.decode("utf-8")
