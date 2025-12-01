"""
Module des contrôleurs d'authentification

Ce module expose tous les contrôleurs d'authentification modulaires :
- RegisterController : Inscription simple sans vérification email
- RegisterVerifiedController : Inscription avec vérification email
- LoginController : Connexion
- LogoutController : Déconnexion
- ResetPasswordController : Réinitialisation du mot de passe
"""

from .login_controller import LoginController
from .logout_controller import LogoutController
from .register_controller import RegisterController
from .register_verified_controller import RegisterVerifiedController
from .reset_password_controller import ResetPasswordController

__all__ = [
    "RegisterController",
    "RegisterVerifiedController",
    "LoginController",
    "LogoutController",
    "ResetPasswordController",
]
