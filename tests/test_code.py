import logging
from datetime import UTC, datetime
from typing import Optional
from urllib.parse import urlencode

from blacksheep import Request, Response, json, redirect, text
from blacksheep.server.controllers import Controller, get, post
from itsdangerous import BadSignature, SignatureExpired

from domain.user_service import UserService


class Users(Controller):
    """
    Contrôleur MVC pour la gestion des utilisateurs

    Routes générées :
    - GET  /users/register              -> Afficher le formulaire d'inscription
    - POST /users/register              -> Traiter l'inscription
    - GET  /users/verify-email/{token}  -> Vérifier l'email
    - GET  /users/resend-verification   -> Afficher le formulaire de renvoi
    - POST /users/resend-verification   -> Renvoyer l'email
    - GET  /users/success               -> Page de succès
    """

    def __init__(self, user_service: UserService):
        self.user_service = user_service

    @classmethod
    def route(cls) -> str:
        """Route de base pour tous les endpoints de ce contrôleur"""
        return "/users"

    @classmethod
    def class_name(cls) -> str:
        """Nom de la classe pour la génération automatique des routes"""
        return "users"

    # Simple register
    @get("/register/view/simple")
    async def simple_register_view(self, request: Request) -> Response:
        return self.view(
            model={
                "title": "Ajouter un utilisateur",
                "error": None,
                "success": None,
                "form_data": {},
            },
        )
