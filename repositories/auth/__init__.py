"""
Module des repositories d'authentification

Ce module expose tous les repositories d'authentification modulaires :
- RegisterRepository : Repository pour l'inscription simple
- RegisterVerifiedRepository : Repository pour l'inscription avec vérification email
- AuthRepository : Repository pour l'authentification (login/logout)
- ResetPasswordRepository : Repository pour la réinitialisation du mot de passe
"""

from .auth_repository import AuthRepository
from .register_repository import RegisterRepository
from .register_verified_repository import RegisterVerifiedRepository
from .reset_password_repository import ResetPasswordRepository

__all__ = [
    "RegisterRepository",
    "RegisterVerifiedRepository",
    "AuthRepository",
    "ResetPasswordRepository",
]
