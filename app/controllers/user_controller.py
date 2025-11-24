import logging
from datetime import UTC, datetime
from typing import Optional
from urllib.parse import urlencode

from blacksheep import Request, Response, json, redirect, text
from blacksheep.server.controllers import Controller, get, post

from domain.user_service import UserService
from helpers.decorators import rate_limit, require_role

"""
UserController - Contrôleur MVC pour la gestion des utilisateurs avec BlackSheep

Responsabilités :
- Affichage des vues HTML (formulaires d'inscription, vérification)
- Traitement des formulaires POST
- Validation des entrées
- Orchestration des services
- Redirection et messages flash

Architecture MVC :
- Model : Pydantic schemas pour validation
- View : Templates Jinja2
- Controller : Cette classe
"""


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

    # @require_role("admin")
    @get("/register/view")
    async def register_view(self) -> Response:
        """
        Afficher le formulaire d'inscription
        """
        return self.view(model={"title": "Inscription", "error": None, "form_data": {}})

    @post("/register")
    @rate_limit(limit=5, per_seconds=3600, scope="register")
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

    @get("/login")
    async def login_view(self, request: Request):
        """Afficher le formulaire de connexion"""
        return self.view(
            "login_view", model={"title": "Connexion", "error": None, "identifier": ""}
        )

    @post("/login")
    @rate_limit(limit=5, per_seconds=300, scope="login")
    async def login(self, request: Request) -> Response:
        """
        Traiter la connexion d'un utilisateur
        """
        try:
            form_data = await request.form()
            identifier = form_data.get("identifier")  # email ou username
            password = form_data.get("password")

            if not identifier or not password:
                return self.view(
                    "login_view",
                    model={
                        "title": "Connexion",
                        "error": "Veuillez renseigner tous les champs",
                        "identifier": identifier or "",
                    },
                )

            # Authentifier l'utilisateur
            user = await self.user_service.authenticate_user(identifier, password)

            if not user:
                return self.view(
                    "login_view",
                    model={
                        "title": "Connexion",
                        "error": "Identifiants incorrects",
                        "identifier": identifier,
                    },
                )

            # Stocker l'utilisateur dans la session
            request.session["_user_id"] = user.id
            request.session["username"] = user.username
            request.session["email"] = user.email
            request.session["authenticated_at"] = datetime.now(UTC).isoformat()

            logger.info(f"User logged in: user_id={user.id}, email={user.email}")

            # Rediriger vers la page d'accueil ou le tableau de bord
            return redirect(
                "/users/home?title=Connexion réussie&message=Bienvenue " + user.username
            )

        except ValueError as e:
            # Compte non activé
            logger.warning(f"Login failed: {str(e)}")
            return self.view(
                "login_view",
                model={
                    "title": "Connexion",
                    "error": str(e),
                    "identifier": identifier,
                    "can_resend": True,
                },
            )

        except Exception as e:
            logger.error(f"Login failed - server error: {str(e)}", exc_info=True)
            return self.view(
                "login_view",
                model={
                    "title": "Connexion",
                    "error": "Une erreur est survenue lors de la connexion",
                    "identifier": identifier,
                },
            )

    @get("/logout")
    async def logout(self, request: Request):
        """Déconnecter l'utilisateur"""
        # Supprimer les données de session
        if "_user_id" in request.session:
            del request.session["_user_id"]
        if "username" in request.session:
            del request.session["username"]
        if "email" in request.session:
            del request.session["email"]
        if "authenticated_at" in request.session:
            del request.session["authenticated_at"]

        return redirect("/?message=Vous êtes  déconnecté")

    # ==========================================
    # RÉINITIALISATION DE MOT DE PASSE
    # ==========================================
    # GET  /users/forgot-password              # Formulaire demande reset
    # POST /users/forgot-password              # Traiter demande reset
    # GET  /users/reset-password/{token}       # Formulaire nouveau mot de passe
    # POST /users/reset-password/{token}       # Traiter nouveau mot de passe

    @get("/forgot-password")
    async def forgot_password_view(self, request: Request) -> Response:
        """Afficher le formulaire de demande de réinitialisation"""
        email = (
            request.query.get("email", [""])[0] if request.query.get("email") else ""
        )

        return self.view(
            "forgot_password",
            model={
                "title": "Mot de passe oublié",
                "error": None,
                "form_data": {"email": email},
            },
        )

    @post("/forgot-password")
    @rate_limit(limit=3, per_seconds=900, scope="forgot-password")
    async def forgot_password(self, request: Request) -> Response:
        """Traiter la demande de réinitialisation"""
        try:
            form_data = await request.form()
            email = form_data.get("email", "").strip()

            if not email:
                return self.view(
                    "forgot_password",
                    model={
                        "title": "Mot de passe oublié",
                        "error": "Veuillez saisir votre adresse email",
                        "form_data": {"email": email},
                    },
                )

            # Demander la réinitialisation
            await self.user_service.request_password_reset(email)

            # Toujours afficher la même page (sécurité)
            return self.view("forgot_password_sent", model={"email": email})

        except Exception as e:
            logger.error(f"Forgot password error: {e}", exc_info=True)
            return self.view(
                "forgot_password",
                model={
                    "title": "Mot de passe oublié",
                    "error": "Une erreur est survenue. Veuillez réessayer.",
                    "form_data": {"email": email if "email" in locals() else ""},
                },
            )

    @get("/reset-password/{token}")
    async def reset_password_view(self, token: str) -> Response:
        """Afficher le formulaire de nouveau mot de passe"""
        # Vérifier la validité du token
        is_valid, message, user = await self.user_service.verify_password_reset_token(
            token
        )

        if not is_valid:
            if message == "expired" and user:
                return self.view("reset_password_expired", model={"email": user.email})

            return self.view(
                "home",
                model={
                    "title": "Lien invalide",
                    "message": message,
                    "can_login": False,
                    "can_resend": False,
                },
            )

        return self.view(
            "reset_password",
            model={"title": "Nouveau mot de passe", "token": token, "error": None},
        )

    @post("/reset-password/{token}")
    async def reset_password(self, token: str, request: Request) -> Response:
        """Traiter la réinitialisation du mot de passe"""
        try:
            form_data = await request.form()
            new_password = form_data.get("new_password", "")
            confirm_password = form_data.get("confirm_password", "")

            # Validation
            if not new_password or not confirm_password:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Veuillez remplir tous les champs",
                    },
                )

            if new_password != confirm_password:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Les mots de passe ne correspondent pas",
                    },
                )

            if len(new_password) < 8:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": "Le mot de passe doit contenir au moins 8 caractères",
                    },
                )

            # Réinitialiser le mot de passe
            success, message = await self.user_service.reset_password(
                token, new_password
            )

            if not success:
                return self.view(
                    "reset_password",
                    model={
                        "title": "Nouveau mot de passe",
                        "token": token,
                        "error": message,
                    },
                )

            # Succès : rediriger vers login
            logger.info("Password reset successful")
            return self.view(
                "login_view",
                model={
                    "title": "Connexion",
                    "success": "Votre mot de passe a été réinitialisé avec succès. Vous pouvez maintenant vous connecter.",
                    "error": None,
                    "identifier": "",
                },
            )

        except Exception as e:
            logger.error(f"Reset password error: {e}", exc_info=True)
            return self.view(
                "reset_password",
                model={
                    "title": "Nouveau mot de passe",
                    "token": token,
                    "error": "Une erreur est survenue. Veuillez réessayer.",
                },
            )

    """
    Route admin pour déboguer
    Ajoutez une route pour voir les stats (à protéger en production) :
    """

    @get("/admin/rate-limits")
    async def admin_rate_limits(self, request: Request) -> Response:
        """Voir les dernières tentatives (admin uniquement)"""
        from sqlalchemy import select

        from dbsession import AsyncSessionLocal
        from model.user import RateLimit

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(RateLimit).order_by(RateLimit.attempted_at.desc()).limit(50)
            )
            attempts = result.scalars().all()

            data = [
                {
                    "id": a.id,
                    "identifier": a.identifier,
                    "endpoint": a.endpoint,
                    "ip": a.ip_address,
                    "time": a.attempted_at.isoformat(),
                }
                for a in attempts
            ]

            from blacksheep import json as json_response

            return json_response(data)


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

    # @post("/login")
    # async def login(self, request: Request):
    #     """Login utilisateur."""
    #     data = await request.json()
    #     username = data.get("username")

    #     if not username:
    #         return json({"error": "Username requis"}, status=400)

    #     # Simuler authentification
    #     user_id = hash(username) % 10000

    #     # Stocker dans la session
    #     request.session["_user_id"] = user_id
    #     request.session["username"] = username
    #     request.session["authenticated_at"] = datetime.now(UTC).isoformat()

    #     return json(
    #         {
    #             "message": f"Connecté en tant que {username}",
    #             "user_id": user_id,
    #         }
    #     )

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
    @rate_limit(limit=10, per_seconds=60, by="ip", scope="session-test")
    async def test_session_persistence(self, request: Request):
        """
        Route de test pour vérifier la persistance des sessions.

        Teste :
        - Création de session anonyme
        - Compteur de visites
        - Vérification en DB
        """
        from sqlalchemy import select

        from dbsession import AsyncSessionLocal
        from model.user import Session as SessionModel

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
        from sqlalchemy import func, select

        from dbsession import AsyncSessionLocal
        from model.user import Session as SessionModel

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
