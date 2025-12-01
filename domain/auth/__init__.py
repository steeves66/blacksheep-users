"""
Module des services d'authentification

Ce module expose tous les services d'authentification modulaires :
- RegisterService : Service pour l'inscription simple
- RegisterVerifiedService : Service pour l'inscription avec vérification email
- AuthService : Service pour l'authentification (login + logout)
- ResetPasswordService : Service pour la réinitialisation du mot de passe
"""

from .auth_service import AuthService
from .register_service import RegisterService
from .register_verified_service import RegisterVerifiedService
from .reset_password_service import ResetPasswordService

__all__ = [
    "RegisterService",
    "RegisterVerifiedService",
    "AuthService",
    "ResetPasswordService",
]
