from blacksheep import Request, text, json, redirect, Response
from blacksheep.server.controllers import Controller, get, post
from datetime import datetime, UTC
from typing import Optional
from urllib.parse import urlencode
from itsdangerous import SignatureExpired, BadSignature

from domain.user_service import UserService

import logging

logger = logging.getLogger(__name__)


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

    @get("/register/view")
    async def register_view(self) -> Response:
        """
        Afficher le formulaire d'inscription
        """
        return self.view(model={"title": "Inscription", "error": None, "form_data": {}})

    @post("/register")
    async def create_user(self, request: Request) -> Response:
        form_data = await request.form()

        username = form_data.get("username")
        email = form_data.get("email")
        password = form_data.get("password")
        confirm_password = form_data.get("confirm_password")

        user, email_sent = await self.user_service.create_user(
            username=username, email=email, password=password
        )

        logger.info(f"User registered successfully: {user.email}")

        return self.view("success", model={"user": user})

    @get("/verify-email/{token}")
    async def verify_email(self, token: str) -> Response:
        """
        Vérifier l'email d'un utilisateur à partir du lien reçu
        """
        success, message, user = await self.user_service.verify_email(token)

        # cas Token expiré
        if message == "expired" and user:
            return redirect(
                f"/users/resend-verification?reason=expired&email={user.email}"
            )

        # CAS 2 : Compte déjà activé (token déjà utilisé)
        if message == "already_active" and user:
            return redirect(f"/users/account-active?email={user.email}")

        if success:
            params = urlencode(
                {
                    "title": "Compte activé",
                    "message": message,
                    "can_login": "1",
                }
            )
            return redirect(f"/users/home?{params}")
        else:
            params = urlencode(
                {
                    "title": "Vérification échouée",
                    "message": message,
                    "can_resend": "1",
                }
            )
            return redirect(f"/users/home?{params}")

    @get("/home")
    async def home(self, request: Request) -> Response:
        title = request.query.get("title")
        message = request.query.get("message")

        can_login = request.query.get("can_login") is not None
        can_resend = request.query.get("can_resend") is not None

        return self.view(
            "home",
            model={
                "title": title,
                "message": message,
                "can_login": can_login,
                "can_resend": can_resend,
            },
        )

    @get("/account-active")
    async def account_active(self, request: Request) -> Response:
        """Page informant que le compte est déjà activé"""
        email_list = request.query.get("email")
        email = email_list[0] if email_list else ""

        return self.view("account_active", model={"email": email})

    # ==========================================
    # RENVOI D'EMAIL
    # ==========================================

    # GET /users/resend-verification?reason=expired&email=user@example.com
    @get("/resend-verification")
    async def resend_verification(self, request: Request) -> Response:
        reason_list = request.query.get("reason", "default")
        email_list = request.query.get("email", "")

        # Extraire la première valeur ou utiliser une valeur par défaut
        reason = reason_list[0] if reason_list else "default"
        email = email_list[0] if email_list else ""

        messages = {
            "expired": "Votre lien a expiré.",
            "not_received": "Vous n'avez pas reçu l'email ?",
            "login_inactive": "Votre compte n'est pas activé.",
            "default": "Entrez votre email pour recevoir un nouveau lien de vérification.",
        }

        return self.view(
            "resend_verification",
            model={
                "context_message": messages.get(reason, messages["default"]),
                "email": email,
                "error": None,
            },
        )

    @post("/resend-verification")
    async def resend_verification_email(self, request: Request) -> Response:
        """
        Traiter le renvoi d'email de vérification
        """
        try:
            # Lire les données du formulaire
            form_data = await request.form()
            email = form_data.get("email", "")

            if not email:
                return self.view(
                    "resend_verification",
                    model={
                        "title": "Renvoyer l'email de vérification",
                        "error": "L'email est requis",
                    },
                )

            # Renvoyer l'email
            email_sent = await self.user_service.resend_verification_email(email)

            if not email_sent:
                logger.error(f"Failed to send verification email to {email}")
                return self.view(
                    "resend_verification",
                    model={
                        "title": "Renvoyer l'email de vérification",
                        "error": "Échec de l'envoi de l'email",
                    },
                )

            logger.info(f"Verification email resent to: {email}")

            return self.view(
                "resend-success", model={"title": "Email renvoyé", "email": email}
            )

        except ValueError as e:
            logger.warning(f"Resend verification failed: {str(e)}")
            return self.view(
                "resend_verification",
                model={"title": "Renvoyer l'email de vérification", "error": str(e)},
            )

        except Exception as e:
            logger.error(
                f"Resend verification failed - server error: {str(e)}", exc_info=True
            )
            return self.view(
                "resend_verification",
                model={
                    "title": "Renvoyer l'email de vérification",
                    "error": "Une erreur est survenue lors de l'envoi de l'email",
                },
            )


class SessionController(Controller):
    """Contrôleur de test des sessions."""

    @classmethod
    def route(cls) -> Optional[str]:
        """Route de base pour ce contrôleur."""
        return ""  # Pas de préfixe, les routes sont directes

    @classmethod
    def class_name(cls) -> str:
        """Nom de classe pour les logs."""
        return "Session"

    @get("/testhome")
    def index(self, request: Request):
        """Test simple de session."""
        # Modifier la session
        session = request.session
        session["example"] = "Lorem ipsum"

        return text(session["example"])

    @post("/login")
    async def login(self, request: Request):
        """Login utilisateur."""
        data = await request.json()
        username = data.get("username")

        if not username:
            return json({"error": "Username requis"}, status=400)

        # Simuler authentification
        user_id = hash(username) % 10000

        # Stocker dans la session
        request.session["_user_id"] = user_id
        request.session["username"] = username
        request.session["authenticated_at"] = datetime.now(UTC).isoformat()

        return json(
            {
                "message": f"Connecté en tant que {username}",
                "user_id": user_id,
            }
        )

    @post("/logout")
    async def logout(self, request: Request):
        """Déconnexion."""
        if "_user_id" in request.session:
            del request.session["_user_id"]
        if "username" in request.session:
            del request.session["username"]

        return json({"message": "Déconnecté"})

    @get("/profile")
    async def profile(self, request: Request):
        """Profil utilisateur."""
        user_id = request.session.get("_user_id")

        if not user_id:
            return json({"error": "Non authentifié"}, status=401)

        return json(
            {
                "user_id": user_id,
                "username": request.session.get("username"),
                "authenticated_at": request.session.get("authenticated_at"),
            }
        )

    @get("/cart")
    async def cart(self, request: Request):
        """Panier (anonyme ou authentifié)."""
        cart = request.session.get("cart", [])

        return json(
            {
                "cart": cart,
                "items_count": len(cart),
                "authenticated": request.session.get("_user_id") is not None,
            }
        )

    @post("/cart/add")
    async def add_to_cart(self, request: Request):
        """Ajouter au panier."""
        data = await request.json()
        product_id = data.get("product_id")

        if not product_id:
            return json({"error": "product_id requis"}, status=400)

        cart = request.session.get("cart", [])
        cart.append(product_id)
        request.session["cart"] = cart

        return json(
            {
                "message": "Produit ajouté",
                "cart": cart,
            }
        )

    @get("/session/test")
    async def test_session_persistence(self, request: Request):
        """
        Route de test pour vérifier la persistance des sessions.

        Teste :
        - Création de session anonyme
        - Compteur de visites
        - Vérification en DB
        """
        from dbsession import AsyncSessionLocal
        from model.user import Session as SessionModel
        from sqlalchemy import select

        # Récupérer ou initialiser le compteur
        visit_count = request.session.get("visit_count", 0)
        visit_count += 1
        request.session["visit_count"] = visit_count
        request.session["last_visit"] = datetime.now(UTC).isoformat()

        # Informations de la session actuelle
        session_id = request.session.get("_session_id", "Pas encore créé")
        user_id = request.session.get("_user_id")

        # Vérifier en base de données
        db_session_exists = False
        db_session_data = None

        if session_id != "Pas encore créé":
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SessionModel).where(SessionModel.id == session_id)
                )
                db_session = result.scalar_one_or_none()

                if db_session:
                    db_session_exists = True
                    db_session_data = {
                        "id": db_session.id[:16] + "...",
                        "user_id": db_session.user_id,
                        "created_at": db_session.created_at.isoformat(),
                        "last_accessed": db_session.last_accessed.isoformat(),
                        "expires_at": db_session.expires_at.isoformat(),
                        "data": db_session.data,
                    }

        return json(
            {
                "status": "success",
                "session_info": {
                    "session_id": session_id
                    if isinstance(session_id, str)
                    else session_id[:16] + "...",
                    "visit_count": visit_count,
                    "last_visit": request.session.get("last_visit"),
                    "is_authenticated": user_id is not None,
                    "user_id": user_id,
                },
                "database_check": {
                    "exists_in_db": db_session_exists,
                    "session_data": db_session_data,
                },
                "instructions": {
                    "1": "Appelez cette route plusieurs fois",
                    "2": "visit_count devrait augmenter",
                    "3": "Vérifiez que exists_in_db = true",
                    "4": "Redémarrez le serveur et réessayez",
                    "5": "La session devrait persister (même visit_count)",
                },
            }
        )

    @get("/session/stats")
    async def session_stats(self, request: Request):
        """Statistiques globales des sessions en DB."""
        from dbsession import AsyncSessionLocal
        from model.user import Session as SessionModel
        from sqlalchemy import select, func

        async with AsyncSessionLocal() as db:
            # Nombre total de sessions
            total_result = await db.execute(select(func.count(SessionModel.id)))
            total_sessions = total_result.scalar()

            # Sessions authentifiées
            auth_result = await db.execute(
                select(func.count(SessionModel.id)).where(
                    SessionModel.user_id.isnot(None)
                )
            )
            authenticated_sessions = auth_result.scalar()

            # Sessions anonymes
            anonymous_sessions = total_sessions - authenticated_sessions

            # Sessions actives (non expirées)
            active_result = await db.execute(
                select(func.count(SessionModel.id)).where(
                    SessionModel.expires_at > datetime.now(UTC)
                )
            )
            active_sessions = active_result.scalar()

            return json(
                {
                    "total_sessions": total_sessions,
                    "authenticated_sessions": authenticated_sessions,
                    "anonymous_sessions": anonymous_sessions,
                    "active_sessions": active_sessions,
                    "expired_sessions": total_sessions - active_sessions,
                }
            )
