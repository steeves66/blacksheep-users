from blacksheep import Request, text, json
from blacksheep.server.controllers import Controller, get, post
from datetime import datetime
from typing import Optional


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
        request.session["authenticated_at"] = datetime.utcnow().isoformat()

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
        request.session["last_visit"] = datetime.utcnow().isoformat()

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
                    SessionModel.expires_at > datetime.utcnow()
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
