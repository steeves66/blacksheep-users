"""
═══════════════════════════════════════════════════════════════════════════
FICHIER 1/2 : app/session_store.py
═══════════════════════════════════════════════════════════════════════════

SessionStore avec base de données et gestion utilisateur.

RESPONSABILITÉS :
- Gestion du cycle de vie des sessions (load, save, destroy)
- Persistance en base de données
- Tracking de sécurité (IP, User-Agent)
- Optimisations de performance
- Cleanup des sessions expirées

SÉPARATION DES RESPONSABILITÉS :
✅ Ce fichier : Gestion technique des sessions
❌ Ce fichier : Pas d'authentification (voir auth_service.py)

═══════════════════════════════════════════════════════════════════════════
"""

import secrets
import json
from datetime import datetime, timedelta, UTC
from typing import Any, Dict, Optional, List

from sqlalchemy import select, delete, update, func
from blacksheep.cookies import Cookie, CookieSameSiteMode
from blacksheep.messages import Request, Response
from blacksheep.sessions.abc import Session, SessionStore

from dbsession import AsyncSessionLocal
from model.user import SessionModel


# ============================================================================
# ÉTAPE 1 : Wrapper de Session pour tracker les modifications
# ============================================================================

class TrackedSession(Session):
    """
    Session qui track automatiquement les modifications.
    
    Objectif : Optimiser les écritures DB en ne sauvegardant
    que les sessions qui ont été réellement modifiées.
    """
    
    def __init__(self, data: Dict[str, Any]):
        super().__init__(data)
        self._is_modified = False
        self._initial_data = json.dumps(data, sort_keys=True)
    
    def __setitem__(self, key: str, value: Any) -> None:
        """Appelé lors de session[key] = value"""
        super().__setitem__(key, value)
        self._is_modified = True
    
    def __delitem__(self, key: str) -> None:
        """Appelé lors de del session[key]"""
        super().__delitem__(key)
        self._is_modified = True
    
    def is_modified(self) -> bool:
        """Vérifie si la session a été modifiée depuis le chargement."""
        if self._is_modified:
            return True
        # Comparaison profonde des données
        current_data = json.dumps(self.to_dict(), sort_keys=True)
        return current_data != self._initial_data
    
    def mark_clean(self) -> None:
        """Marque la session comme non modifiée après sauvegarde."""
        self._is_modified = False
        self._initial_data = json.dumps(self.to_dict(), sort_keys=True)


# ============================================================================
# ÉTAPE 2 : SessionStore principal
# ============================================================================

class DatabaseSessionStore(SessionStore):
    """
    SessionStore avec base de données et support utilisateur.
    
    RESPONSABILITÉS :
    - Load/Save des sessions depuis/vers la DB
    - Validation de sécurité (IP, User-Agent)
    - Gestion du cycle de vie des sessions
    - Optimisations de performance
    - Statistiques et maintenance
    
    NE GÈRE PAS :
    - L'authentification utilisateur (voir AuthService)
    - La logique métier (voir controllers/routes)
    """

    def __init__(
        self,
        cookie_name: str = "session",
        session_lifetime: int = 86400,  # 24 heures
        track_ip: bool = True,
        track_user_agent: bool = True,
        secure: bool = False,
        same_site: str = "lax",
        strict_security: bool = True,
        anonymous_lifetime: int = 3600,  # 1h pour anonymes (optionnel)
    ):
        self._session_cookie_name = cookie_name
        self._session_lifetime = session_lifetime
        self._anonymous_lifetime = anonymous_lifetime  # ✅ AJOUT
        self._track_ip = track_ip
        self._track_user_agent = track_user_agent
        self._secure = secure
        self._strict_security = strict_security
        
        same_site_map = {
            "strict": CookieSameSiteMode.STRICT,
            "lax": CookieSameSiteMode.LAX,
            "none": CookieSameSiteMode.NONE,
        }
        self._same_site = same_site_map.get(same_site.lower(), CookieSameSiteMode.LAX)

        # Extensions et chemins à exclure
        self._static_extensions = {
            b".css", b".js", b".png", b".jpg", b".jpeg", b".gif", b".svg",
            b".woff", b".woff2", b".ttf", b".ico", b".map", b".webp",
            b".avif", b".eot",
        }
        self._static_paths = {
            b"/static/", b"/vendor/", b"/images/", b"/scripts/",
            b"/styles/", b"/fonts/", b"/assets/",
        }

        print(f"🔧 DatabaseSessionStore initialisé")
        print(f"   📛 Cookie: {cookie_name}")
        print(f"   ⏱️  Durée: {session_lifetime}s ({session_lifetime // 3600}h)")
        print(f"   🔒 Secure: {secure}, SameSite: {same_site}")
        print(f"   🛡️  Strict Security: {strict_security}")

    # ========================================================================
    # Helpers : Détection fichiers statiques et tracking
    # ========================================================================

    def _is_static_file(self, path: bytes) -> bool:
        """
        Vérifie si le chemin est un fichier statique à exclure.
        
        Optimisation : Éviter de créer des sessions pour .css, .js, etc.
        """
        for static_path in self._static_paths:
            if static_path in path:
                return True
        for ext in self._static_extensions:
            if path.endswith(ext):
                return True
        return False

    def _get_client_ip(self, request: Request) -> Optional[str]:
        """
        Récupère l'IP du client en tenant compte des proxies.
        
        Ordre de priorité :
        1. X-Forwarded-For (premier IP)
        2. X-Real-IP
        3. IP de connexion directe
        """
        if not self._track_ip:
            return None

        forwarded = request.get_first_header(b"X-Forwarded-For")
        if forwarded:
            return forwarded.decode("utf-8").split(",")[0].strip()

        real_ip = request.get_first_header(b"X-Real-IP")
        if real_ip:
            return real_ip.decode("utf-8")

        client = getattr(request, "scope", {}).get("client")
        if client:
            return client[0]

        return None

    def _get_user_agent(self, request: Request) -> Optional[str]:
        """Récupère le User-Agent du client (limité à 255 caractères)."""
        if not self._track_user_agent:
            return None

        user_agent = request.get_first_header(b"User-Agent")
        if user_agent:
            ua_str = user_agent.decode("utf-8")
            return ua_str[:255] if len(ua_str) > 255 else ua_str

        return None

    # ========================================================================
    # Validation de sécurité
    # ========================================================================

    def _validate_session_security(
        self, session_model: SessionModel, request: Request
    ) -> bool:
        """
        ✅ VALIDATION ACTIVE : Vérifie IP et User-Agent.
        
        Retourne False si la session est compromise, ce qui provoque
        sa suppression automatique.
        
        Args:
            session_model: Session chargée depuis la DB
            request: Requête HTTP actuelle
            
        Returns:
            bool: True si la session est sûre, False sinon
        """
        # Vérification IP
        if self._track_ip and session_model.ip_address:
            current_ip = self._get_client_ip(request)
            if current_ip and current_ip != session_model.ip_address:
                print(f"🚨 SÉCURITÉ : IP mismatch détecté")
                print(f"   Session IP: {session_model.ip_address}")
                print(f"   Current IP: {current_ip}")
                
                if self._strict_security:
                    return False

        # Vérification User-Agent
        if self._track_user_agent and session_model.user_agent:
            current_ua = self._get_user_agent(request)
            if current_ua and current_ua != session_model.user_agent:
                print(f"🚨 SÉCURITÉ : User-Agent mismatch détecté")
                
                if self._strict_security:
                    return False

        return True

    # ========================================================================
    # Cycle de vie : Load
    # ========================================================================

    async def load(self, request: Request) -> Session:
        """
        Charge la session associée à la requête.
        
        ÉTAPES :
        1. Exclure les fichiers statiques
        2. Récupérer le cookie de session
        3. Charger depuis la DB si existe
        4. Valider la sécurité (IP, User-Agent, expiration)
        5. Créer une nouvelle session si nécessaire
        
        Returns:
            TrackedSession: Session chargée ou nouvelle
        """
        # Exclure les fichiers statiques
        if self._is_static_file(request.url.path):
            return TrackedSession({})

        session_id = request.cookies.get(self._session_cookie_name)

        if session_id:
            try:
                async with AsyncSessionLocal() as db_session:
                    result = await db_session.execute(
                        select(SessionModel).where(SessionModel.id == session_id)
                    )
                    session_model = result.scalar_one_or_none()

                    if session_model:
                        # Vérifier l'expiration
                        if session_model.expires_at > datetime.now(UTC):
                            # Valider la sécurité
                            if not self._validate_session_security(session_model, request):
                                print(f"🚨 Session {session_id[:8]}... invalidée (sécurité)")
                                await db_session.delete(session_model)
                                await db_session.commit()
                                return self._create_new_session()
                            
                            # Session valide : charger les données
                            session_data = json.loads(session_model.data)
                            
                            # Injecter les métadonnées
                            session_data["_id"] = session_id
                            if session_model.user_id:
                                session_data["_user_id"] = session_model.user_id
                            
                            print(f"✅ Session {session_id[:8]}... chargée")
                            if session_model.user_id:
                                print(f"   👤 User ID: {session_model.user_id}")
                            
                            return TrackedSession(session_data)
                        else:
                            print(f"⏰ Session {session_id[:8]}... expirée")
                            await db_session.delete(session_model)
                            await db_session.commit()
            except Exception as e:
                print(f"❌ Erreur load session: {e}")

        # Créer une nouvelle session
        return self._create_new_session()

    def _create_new_session(self) -> TrackedSession:
        """Crée une nouvelle session avec un ID unique."""
        session_id = secrets.token_urlsafe(32)
        session = TrackedSession({
            "_id": session_id,
            "_created_at": datetime.now(UTC).isoformat(),
            "_is_new": True,
        })
        print(f"🆕 Nouvelle session {session_id[:8]}... créée")
        return session

    # ========================================================================
    # Cycle de vie : Save
    # ========================================================================

    async def save(
        self, request: Request, response: Response, session: Session
    ) -> None:
        """
        Sauvegarde la session dans la base de données.
        
        ✅ OPTIMISATION : Ne sauvegarde que si la session est modifiée.
        Toujours mettre à jour last_accessed et expires_at.
        
        ÉTAPES :
        1. Exclure les fichiers statiques
        2. Vérifier si la session est modifiée
        3. Récupérer les métadonnées (IP, User-Agent, user_id)
        4. Sauvegarder en DB (INSERT ou UPDATE)
        5. Définir le cookie
        """
        # Exclure les fichiers statiques
        if self._is_static_file(request.url.path):
            return

        current_session = request.session
        session_id = current_session.get("_id")

        if not session_id:
            session_id = secrets.token_urlsafe(32)
            current_session["_id"] = session_id

        # ✅ AJOUT : Forcer la modification pour les nouvelles sessions
        if current_session.get("_is_new"):
            is_modified = True
        #     # Retirer le flag après la première sauvegarde
        #     if "_is_new" in current_session:
        #         del current_session["_is_new"]
        # else:
        #     # Vérifier si la session a été modifiée
        #     if isinstance(current_session, TrackedSession):
        #         is_modified = current_session.is_modified()
        #     else:
        #         is_modified = True

        # Récupérer les informations
        ip_address = self._get_client_ip(request)
        user_agent = self._get_user_agent(request)
        user_id = current_session.get("_user_id")
        if user_id:
            # Session authentifiée : durée de vie longue
            lifetime = self._session_lifetime
        else:
            # Session anonyme : durée de vie courte
            lifetime = self._anonymous_lifetime

        expires_at = datetime.now(UTC) + timedelta(seconds=lifetime)
        now = datetime.now(UTC)

        # Sérialiser les données (sans les métadonnées internes)
        session_dict = current_session.to_dict()
        data_to_save = {k: v for k, v in session_dict.items() 
                       if not k.startswith("_") or k == "_user_id"}
        session_data = json.dumps(data_to_save)

        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(
                    select(SessionModel).where(SessionModel.id == session_id)
                )
                session_model = result.scalar_one_or_none()

                if session_model:
                    # Mise à jour session existante
                    print(f"🔄 [SAVE] Session existante trouvée, mise à jour...")
                    if is_modified:
                        session_model.data = session_data
                        session_model.user_id = user_id
                        session_model.last_accessed = now
                        session_model.expires_at = expires_at
                        print(f"🔄 Session {session_id[:8]}... mise à jour (modifiée)")
                        
                    
                    # Toujours mettre à jour last_accessed et expires_at
                    # session_model.last_accessed = now
                    # session_model.expires_at = expires_at
                    # print(f"🔄 Session {session_id[:8]}... mise à jour (modifiée)")
                    
                    if not is_modified:
                        print(f"⏱️  Session {session_id[:8]}... last_accessed mis à jour")
                else:
                    # # Création nouvelle session
                    # created_at = datetime.fromisoformat(
                    #     current_session.get("_created_at", now.isoformat())
                    # )
                    print(f"➕ [SAVE] Nouvelle session, création...")
                    created_at = now
                    if "_created_at" in current_session:
                        try:
                            created_at = datetime.fromisoformat(current_session["_created_at"])
                        except:
                            pass
                    session_model = SessionModel(
                        id=session_id,
                        user_id=user_id,
                        data=session_data,
                        created_at=created_at,
                        last_accessed=now,
                        expires_at=expires_at,
                        ip_address=ip_address,
                        user_agent=user_agent,
                    )
                    db_session.add(session_model)
                    print(f"➕ Session {session_id[:8]}... créée en DB")
                    if user_id:
                        print(f"   👤 Liée à User ID: {user_id}")

                await db_session.commit()
                print(f"✅ [SAVE] Commit réussi")
                
                # Marquer comme propre après sauvegarde
                if isinstance(current_session, TrackedSession):
                    current_session.mark_clean()
                
        except Exception as e:
            print(f"❌ Erreur save session: {e}")
            import traceback
            traceback.print_exc()
            return

        # Définir le cookie
        response.set_cookie(
            Cookie(
                self._session_cookie_name,
                session_id,
                http_only=True,
                secure=self._secure,
                same_site=self._same_site,
                path="/",
                max_age=self._session_lifetime,
            )
        )

    # ========================================================================
    # Cycle de vie : Regenerate & Destroy
    # ========================================================================

    async def regenerate_id(self, request: Request) -> str:
        """
        Régénère l'ID de session (protection contre session fixation).
        
        À appeler après une authentification réussie.
        
        Returns:
            str: Le nouvel ID de session
        """
        old_session = request.session
        old_id = old_session.get("_id")

        # Générer un nouvel ID
        new_id = secrets.token_urlsafe(32)

        # Copier toutes les données
        session_data = old_session.to_dict()
        session_data["_id"] = new_id
        session_data["_is_new"] = True

        try:
            async with AsyncSessionLocal() as db_session:
                # Supprimer l'ancienne session
                if old_id:
                    await db_session.execute(
                        delete(SessionModel).where(SessionModel.id == old_id)
                    )

                # Mettre à jour la session actuelle
                old_session.clear()
                old_session.update(session_data)

                await db_session.commit()
                print(f"🔄 Session régénérée: {old_id[:8] if old_id else 'new'}... → {new_id[:8]}...")
        except Exception as e:
            print(f"❌ Erreur regenerate_id: {e}")

        return new_id

    async def destroy(self, request: Request, response: Response) -> None:
        """
        Détruit complètement la session.
        
        À appeler lors de la déconnexion.
        """
        session_id = request.session.get("_id")

        if session_id:
            try:
                async with AsyncSessionLocal() as db_session:
                    await db_session.execute(
                        delete(SessionModel).where(SessionModel.id == session_id)
                    )
                    await db_session.commit()
                    print(f"🗑️  Session {session_id[:8]}... détruite")
            except Exception as e:
                print(f"❌ Erreur destroy: {e}")

        response.unset_cookie(self._session_cookie_name)
        request.session.clear()

    # ========================================================================
    # Gestion multi-sessions par utilisateur
    # ========================================================================

    async def get_sessions_by_user(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Récupère toutes les sessions actives d'un utilisateur.
        
        Utile pour :
        - Afficher les sessions actives dans le profil
        - Gérer les appareils connectés
        - Auditer l'activité
        
        Args:
            user_id: L'ID de l'utilisateur
            
        Returns:
            Liste de dictionnaires avec les infos des sessions
        """
        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(
                    select(SessionModel)
                    .where(SessionModel.user_id == user_id)
                    .where(SessionModel.expires_at > datetime.now(UTC))
                )
                sessions = result.scalars().all()

                return [
                    {
                        "session_id": s.id[:16] + "...",
                        "created_at": s.created_at,
                        "last_accessed": s.last_accessed,
                        "ip_address": s.ip_address,
                        "user_agent": s.user_agent[:50] + "..." if s.user_agent and len(s.user_agent) > 50 else s.user_agent,
                    }
                    for s in sessions
                ]
        except Exception as e:
            print(f"❌ Erreur get_sessions_by_user: {e}")
            return []

    async def destroy_all_user_sessions(
        self, user_id: int, except_session_id: Optional[str] = None
    ) -> int:
        """
        Détruit toutes les sessions d'un utilisateur.
        
        Utile pour :
        - "Déconnecter tous les appareils"
        - Forcer réauthentification après changement de mot de passe
        
        Args:
            user_id: L'ID de l'utilisateur
            except_session_id: Session à préserver (optionnel)
            
        Returns:
            int: Nombre de sessions détruites
        """
        try:
            async with AsyncSessionLocal() as db_session:
                query = delete(SessionModel).where(SessionModel.user_id == user_id)
                
                if except_session_id:
                    query = query.where(SessionModel.id != except_session_id)
                
                result = await db_session.execute(query)
                await db_session.commit()
                
                deleted_count = result.rowcount
                print(f"🗑️  {deleted_count} sessions détruites pour user {user_id}")
                
                return deleted_count
        except Exception as e:
            print(f"❌ Erreur destroy_all_user_sessions: {e}")
            return 0

    # ========================================================================
    # Maintenance et statistiques
    # ========================================================================

    async def cleanup_expired(self, batch_size: int = 100) -> int:
        """
        Supprime les sessions expirées de la base de données.
        
        À appeler périodiquement (ex: toutes les heures).
        
        Args:
            batch_size: Nombre de sessions à supprimer par lot
            
        Returns:
            int: Nombre total de sessions supprimées
        """
        total_deleted = 0

        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(
                    delete(SessionModel).where(
                        SessionModel.expires_at < datetime.now(UTC)
                    )
                )
                await db_session.commit()
                total_deleted = result.rowcount

                if total_deleted > 0:
                    print(f"🧹 {total_deleted} sessions expirées supprimées")
        except Exception as e:
            print(f"❌ Erreur cleanup: {e}")

        return total_deleted

    async def get_session_stats(self) -> Dict[str, Any]:
        """
        Retourne des statistiques sur les sessions.
        
        Returns:
            Dict avec 'total', 'active', 'expired', 'authenticated', 'anonymous', 'unique_users'
        """
        try:
            async with AsyncSessionLocal() as db_session:
                # Total de sessions
                total_result = await db_session.execute(
                    select(func.count()).select_from(SessionModel)
                )
                total = total_result.scalar()

                # Sessions actives (non expirées)
                active_result = await db_session.execute(
                    select(func.count())
                    .select_from(SessionModel)
                    .where(SessionModel.expires_at > datetime.now(UTC))
                )
                active = active_result.scalar()

                # Sessions authentifiées
                authenticated_result = await db_session.execute(
                    select(func.count())
                    .select_from(SessionModel)
                    .where(SessionModel.user_id.isnot(None))
                    .where(SessionModel.expires_at > datetime.now(UTC))
                )
                authenticated = authenticated_result.scalar()

                # Nombre d'utilisateurs uniques connectés
                unique_users_result = await db_session.execute(
                    select(func.count(func.distinct(SessionModel.user_id)))
                    .select_from(SessionModel)
                    .where(SessionModel.user_id.isnot(None))
                    .where(SessionModel.expires_at > datetime.now(UTC))
                )
                unique_users = unique_users_result.scalar()

                expired = total - active

                return {
                    "total": total,
                    "active": active,
                    "expired": expired,
                    "authenticated": authenticated,
                    "anonymous": active - authenticated,
                    "unique_users": unique_users,
                }
        except Exception as e:
            print(f"❌ Erreur get_session_stats: {e}")
            return {
                "total": 0,
                "active": 0,
                "expired": 0,
                "authenticated": 0,
                "anonymous": 0,
                "unique_users": 0,
            }

    async def cleanup_anonymous_sessions(self, max_age_hours: int = 24) -> int:
        """
        Supprime les sessions anonymes inactives depuis X heures.
        
        Les sessions authentifiées sont préservées plus longtemps.
        
        Args:
            max_age_hours: Âge maximum en heures pour les sessions anonymes
            
        Returns:
            int: Nombre de sessions supprimées
        """
        cutoff_time = datetime.now(UTC) - timedelta(hours=max_age_hours)
        
        try:
            async with AsyncSessionLocal() as db_session:
                result = await db_session.execute(
                    delete(SessionModel).where(
                        SessionModel.user_id.is_(None),  # Seulement anonymes
                        SessionModel.last_accessed < cutoff_time
                    )
                )
                await db_session.commit()
                deleted = result.rowcount
                
                if deleted > 0:
                    print(f"🧹 {deleted} sessions anonymes supprimées (inactives > {max_age_hours}h)")
                
                return deleted
                
        except Exception as e:
            print(f"❌ Erreur cleanup_anonymous_sessions: {e}")
            return 0
   
    # ========================================================================
    # Helpers publics pour l'authentification
    # ========================================================================

    def get_current_user_id(self, request: Request) -> Optional[int]:
        """
        Récupère l'ID de l'utilisateur courant.
        
        Returns:
            int | None: L'ID utilisateur ou None si non authentifié
        """
        return request.session.get("_user_id")

    def is_authenticated(self, request: Request) -> bool:
        """
        Vérifie si l'utilisateur est authentifié.
        
        Returns:
            bool: True si authentifié, False sinon
        """
        return request.session.get("authenticated", False) and \
               request.session.get("_user_id") is not None