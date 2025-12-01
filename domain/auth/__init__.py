"""
Module des services d'authentification

Ce module expose tous les services d'authentification modulaires :
- RegisterService : Service pour l'inscription simple
- RegisterVerifiedService : Service pour l'inscription avec vérification email
- LoginService : Service pour l'authentification
- ResetPasswordService : Service pour la réinitialisation du mot de passe
"""

from .login_service import LoginService
from .register_service import RegisterService
from .register_verified_service import RegisterVerifiedService
from .reset_password_service import ResetPasswordService

__all__ = [
    "RegisterService",
    "RegisterVerifiedService",
    "LoginService",
    "ResetPasswordService",
]
