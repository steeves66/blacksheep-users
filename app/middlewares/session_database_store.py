import secrets
import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select, delete
from blacksheep import Request, Response
from blacksheep.cookies import Cookie, CookieSameSiteMode
from blacksheep.sessions.abc import SessionStore, Session

from dbsession import AsyncSessionLocal
from model.user import Session as SessionModel


class DatabaseSessionStore(SessionStore):
    """
    SessionStore avec persistance en base de données.

    Hérite de SessionStore de BlackSheep et implémente :
    - load() : Charge les données de session et retourne un objet Session
    - save() : Sauvegarde les données de session

    Référence : https://www.neoteroi.dev/blacksheep/sessions/#implementing-a-custom-sessionstore
    """

    def __init__(
        self,
        cookie_name: str = "session_id",
        session_max_age: int = 86400,
        anonymous_max_age: int = 3600,
        same_site: str = "lax",
        http_only: bool = True,
        secure: bool = False,
    ):
        self.cookie_name = cookie_name
        self.session_max_age = session_max_age
        self.anonymous_max_age = anonymous_max_age
        self.same_site = self._parse_same_site(same_site)
        self.http_only = http_only
        self.secure = secure

    def _parse_same_site(self, value: str) -> CookieSameSiteMode:
        """Convertit la chaîne en CookieSameSiteMode."""
        mapping = {
            "strict": CookieSameSiteMode.STRICT,
            "lax": CookieSameSiteMode.LAX,
            "none": CookieSameSiteMode.NONE,
        }
        return mapping.get(value.lower(), CookieSameSiteMode.LAX)

    async def load(self, request: Request) -> Session:
        """
        Charge la session depuis la base de données.

        Cette méthode est appelée automatiquement par BlackSheep
        pour chaque requête.

        Args:
            request: La requête HTTP

        Returns:
            Session: Objet Session de BlackSheep
        """
        session_id = request.cookies.get(self.cookie_name)

        if not session_id:
            return Session()

        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SessionModel).where(SessionModel.id == session_id)
                )
                db_session = result.scalar_one_or_none()

                if not db_session:
                    return Session()

                # Vérifier l'expiration
                if db_session.expires_at < datetime.utcnow():
                    await db.delete(db_session)
                    await db.commit()
                    return Session()

                # Charger et retourner les données
                data = json.loads(db_session.data)
                data["_session_id"] = db_session.id
                data["_user_id"] = db_session.user_id

                # Créer l'objet Session avec les données
                session = Session()
                session.update(data)
                return session

        except Exception as e:
            print(f"Error loading session: {e}")
            return Session()

    async def save(
        self, request: Request, response: Response, session: Session
    ) -> None:
        """
        Sauvegarde la session en base de données.

        Cette méthode est appelée automatiquement par BlackSheep
        après chaque requête si la session a été modifiée.

        Args:
            request: La requête HTTP
            response: La réponse HTTP
            session: Objet Session contenant les données à sauvegarder
        """
        # Extraire les données de manière sûre
        session_data = {}
        if hasattr(session, "_values"):
            session_data = (
                session._values.copy() if isinstance(session._values, dict) else {}
            )

        if not session_data:
            print("DEBUG: session_data is empty, returning")
            return

        # Récupérer ou créer un ID
        session_id = session_data.get("_session_id")
        if not session_id:
            session_id = secrets.token_urlsafe(32)
            session["_session_id"] = session_id
            session_data["_session_id"] = session_id
            print(f"DEBUG: Created NEW session_id = {session_id[:16]}...")
        else:
            print(f"DEBUG: Using EXISTING session_id = {session_id[:16]}...")

        # Extraire les métadonnées
        user_id = session_data.get("_user_id")

        # Calculer l'expiration
        max_age = self.session_max_age if user_id else self.anonymous_max_age
        expires_at = datetime.utcnow() + timedelta(seconds=max_age)
        now = datetime.utcnow()

        # Préparer les données à sauvegarder (exclure les métadonnées internes)
        data_to_save = {
            k: v
            for k, v in session_data.items()
            if not k.startswith("_") or k == "_user_id"
        }
        data_json = json.dumps(data_to_save)

        print(
            f"DEBUG: Saving to DB - session_id={session_id[:16]}..., data={data_json}"
        )

        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    select(SessionModel).where(SessionModel.id == session_id)
                )
                db_session = result.scalar_one_or_none()

                if db_session:
                    print(f"DEBUG: UPDATING existing session in DB")
                    # Mise à jour
                    db_session.data = data_json
                    db_session.user_id = user_id
                    db_session.last_accessed = now
                    db_session.expires_at = expires_at
                else:
                    print(f"DEBUG: CREATING new session in DB")
                    # Création
                    db_session = SessionModel(
                        id=session_id,
                        user_id=user_id,
                        data=data_json,
                        created_at=now,
                        last_accessed=now,
                        expires_at=expires_at,
                        ip_address=request.client_ip
                        if hasattr(request, "client_ip")
                        else None,
                        user_agent=request.get_first_header(b"User-Agent").decode()
                        if request.get_first_header(b"User-Agent")
                        else None,
                    )
                    db.add(db_session)

                await db.commit()
                print(f"DEBUG: DB commit successful!")

        except Exception as e:
            print(f"ERROR saving session: {e}")
            import traceback

            traceback.print_exc()
            return

        # Définir le cookie
        cookie = Cookie(
            name=self.cookie_name,
            value=session_id,
            max_age=max_age,
            http_only=self.http_only,
            secure=self.secure,
            same_site=self.same_site,
            path="/",
        )
        response.set_cookie(cookie)
        print(
            f"DEBUG: Cookie set - name={self.cookie_name}, value={session_id[:16]}..., max_age={max_age}"
        )
