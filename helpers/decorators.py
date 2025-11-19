"""
Décorateurs RBAC v3 pour BlackSheep - REFACTORISÉ

Utilise le UserRepository pour toutes les opérations de base de données
au lieu de faire des requêtes SQL directes.

Avantages :
- Respect du pattern Repository
- Code plus maintenable
- Logique centralisée
- Meilleure testabilité
"""

from functools import wraps
from typing import List, Callable, Optional
from blacksheep import Request, Response, redirect, json as json_response
import logging
from datetime import datetime, UTC, timedelta

logger = logging.getLogger(__name__)


# ==========================================
# HELPER FUNCTIONS
# ==========================================


def get_current_user_id(request: Request) -> int | None:
    """Récupère l'ID de l'utilisateur connecté depuis la session"""
    return request.session.get("_user_id")


def is_authenticated(request: Request) -> bool:
    """Vérifie si l'utilisateur est authentifié"""
    return get_current_user_id(request) is not None


async def get_user_with_rbac(request: Request):
    """
    Récupère l'utilisateur avec ses rôles et permissions

    ✅ UTILISE LE REPOSITORY au lieu de requêtes SQL directes

    Returns:
        User avec relations roles et direct_permissions chargées
    """
    user_id = get_current_user_id(request)

    if not user_id:
        return None

    from dbsession import AsyncSessionLocal
    from repositories.user_repository import UserRepository
    from app.settings import load_settings

    settings = load_settings()

    async with AsyncSessionLocal() as db:
        repo = UserRepository(db, settings)

        # ✅ Utiliser la méthode du repository
        user = await repo.get_user_with_roles_and_permissions(user_id)

        return user


async def check_user_has_role(request: Request, role_name: str) -> bool:
    """
    Vérifie si l'utilisateur a un rôle spécifique

    ✅ Option 1 : Utiliser le repository directement (plus efficace)
    """
    user_id = get_current_user_id(request)

    if not user_id:
        return False

    from dbsession import AsyncSessionLocal
    from repositories.user_repository import UserRepository
    from app.settings import load_settings

    settings = load_settings()

    async with AsyncSessionLocal() as db:
        repo = UserRepository(db, settings)
        return await repo.user_has_role(user_id, role_name)


async def check_user_has_permission(request: Request, permission_name: str) -> bool:
    """
    Vérifie si l'utilisateur a une permission (directe ou via rôle)

    ✅ Utilise le repository qui gère les permissions expirées
    """
    user_id = get_current_user_id(request)

    if not user_id:
        return False

    from dbsession import AsyncSessionLocal
    from repositories.user_repository import UserRepository
    from app.settings import load_settings

    settings = load_settings()

    async with AsyncSessionLocal() as db:
        repo = UserRepository(db, settings)
        return await repo.user_has_permission(user_id, permission_name)


def create_forbidden_response(
    request: Request,
    message: str = "Accès refusé",
    required_role: str = None,
    required_permission: str = None,
) -> Response:
    """Crée une réponse d'erreur 403 (Forbidden)"""
    accept_header = request.get_first_header(b"Accept")
    is_api_request = accept_header and b"application/json" in accept_header

    if is_api_request:
        return json_response(
            {
                "error": message,
                "required_role": required_role,
                "required_permission": required_permission,
            },
            status=403,
        )
    else:
        from urllib.parse import urlencode

        params = urlencode(
            {
                "message": message,
                "required_role": required_role or "",
                "required_permission": required_permission or "",
            }
        )

        return redirect(f"/error/forbidden?{params}")


def create_unauthorized_response(request: Request) -> Response:
    """Crée une réponse d'erreur 401 (Unauthorized)"""
    accept_header = request.get_first_header(b"Accept")
    is_api_request = accept_header and b"application/json" in accept_header

    if is_api_request:
        return json_response(
            {"error": "Non authentifié", "message": "Vous devez être connecté"},
            status=401,
        )
    else:
        from urllib.parse import urlencode

        params = urlencode({"next": request.url.path, "reason": "auth_required"})
        return redirect(f"/users/login?{params}")


# ==========================================
# DÉCORATEURS DE RATE LIMITING
# ==========================================


def _get_client_ip(request: Request) -> str:
    """
    Retourne l'adresse IP du client si disponible.

    Fonction de secours : si l'IP n'est pas disponible, retourne 'unknown'.
    """
    # `client_ip` peut être ajouté par un middleware de proxy / remotes
    ip = getattr(request, "client_ip", None)
    if ip:
        return ip

    client = getattr(request, "client", None)
    if client and getattr(client, "host", None):
        return client.host

    return "unknown"


def _build_rate_limit_identifier(
    request: Request, by: str = "ip_or_user"
) -> tuple[str, str]:
    """
    Construit l'identifiant de rate limit et l'endpoint.

    - by = 'ip'         -> IP uniquement
    - by = 'user'       -> user_id (si connecté), sinon IP
    - by = 'ip_or_user' -> user_id si connecté, sinon IP
    """
    user_id = get_current_user_id(request)
    ip = _get_client_ip(request)

    if by == "user" and user_id:
        identifier = f"user:{user_id}"
    elif by in ("ip",):
        identifier = f"ip:{ip}"
    else:
        # ip_or_user (par défaut)
        if user_id:
            identifier = f"user:{user_id}"
        else:
            identifier = f"ip:{ip}"

    endpoint = request.url.path
    return identifier, endpoint


async def _check_rate_limit(
    request: Request,
    limit: int,
    per_seconds: int,
    by: str = "ip_or_user",
    scope: Optional[str] = None,
) -> tuple[bool, Optional[Response]]:
    """
    Vérifie si la requête dépasse le rate limit.

    Returns:
        (allowed, response) :
            - allowed = False => il faut retourner `response` (429)
            - allowed = True  => continuer le handler
    """
    from dbsession import AsyncSessionLocal
    from sqlalchemy import select, func
    from model.user import RateLimit

    identifier, endpoint = _build_rate_limit_identifier(request, by=by)
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(seconds=per_seconds)

    # On utilise `scope` pour regrouper plusieurs endpoints sous la même règle si besoin
    logical_endpoint = scope or endpoint

    async with AsyncSessionLocal() as db:
        # Compter les tentatives récentes
        stmt = (
            select(func.count(RateLimit.id))
            .where(RateLimit.identifier == identifier)
            .where(RateLimit.endpoint == logical_endpoint)
            .where(RateLimit.attempted_at >= window_start)
        )
        result = await db.execute(stmt)
        attempts = result.scalar() or 0

        if attempts >= limit:
            logger.warning(
                "Rate limit exceeded: identifier=%s endpoint=%s attempts=%s limit=%s",
                identifier,
                logical_endpoint,
                attempts,
                limit,
            )

            # Enregistrer tout de même la tentative pour l'audit
            rate_entry = RateLimit(
                identifier=identifier,
                endpoint=logical_endpoint,
                ip_address=_get_client_ip(request),
                user_agent=(
                    request.get_first_header(b"User-Agent").decode()
                    if request.get_first_header(b"User-Agent")
                    else None
                ),
            )
            db.add(rate_entry)
            await db.commit()

            # Construire une réponse 429 cohérente (JSON ou HTML)
            accept_header = request.get_first_header(b"Accept")
            is_api_request = accept_header and b"application/json" in accept_header

            retry_after = per_seconds  # simple : conseillons d'attendre la fenêtre

            if is_api_request:
                return False, json_response(
                    {
                        "error": "too_many_requests",
                        "message": "Trop de tentatives, veuillez réessayer plus tard.",
                        "limit": limit,
                        "per_seconds": per_seconds,
                    },
                    status=429,
                    headers=[(b"Retry-After", str(retry_after).encode())],
                )
            else:
                from urllib.parse import urlencode

                params = urlencode(
                    {
                        "message": "Trop de tentatives, veuillez réessayer plus tard.",
                        "retry_after": retry_after,
                    }
                )
                response = redirect(f"/error/rate-limit?{params}")
                response.add_header(b"Retry-After", str(retry_after).encode())
                return False, response

        # Enregistrer la tentative courante
        rate_entry = RateLimit(
            identifier=identifier,
            endpoint=logical_endpoint,
            ip_address=_get_client_ip(request),
            user_agent=(
                request.get_first_header(b"User-Agent").decode()
                if request.get_first_header(b"User-Agent")
                else None
            ),
        )
        db.add(rate_entry)
        await db.commit()

    return True, None


def rate_limit(
    limit: int,
    per_seconds: int,
    by: str = "ip_or_user",
    scope: Optional[str] = None,
):
    """
    Décorateur générique de rate limiting.

    Exemple :
        @rate_limit(limit=5, per_seconds=60, by="ip_or_user", scope="login")
        @post("/login")
        async def login(self, request: Request): ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Récupérer l'objet Request comme dans les autres décorateurs
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found in decorator arguments")

            allowed, response = await _check_rate_limit(
                request,
                limit=limit,
                per_seconds=per_seconds,
                by=by,
                scope=scope,
            )

            if not allowed:
                return response

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# DÉCORATEURS D'AUTHENTIFICATION
# ==========================================


def require_auth(func: Callable) -> Callable:
    """
    Décorateur : Requiert une authentification
    """

    @wraps(func)
    async def wrapper(*args, **kwargs):
        request = None
        for arg in args:
            if isinstance(arg, Request):
                request = arg
                break

        if not request:
            request = kwargs.get("request")

        if not request:
            raise ValueError("Request object not found in decorator arguments")

        if not is_authenticated(request):
            logger.warning(f"Unauthorized access attempt: {request.url.path}")
            return create_unauthorized_response(request)

        return await func(*args, **kwargs)

    return wrapper


# ==========================================
# DÉCORATEURS DE RÔLES
# ==========================================


def require_role(role_name: str):
    """
    Décorateur : Requiert un rôle spécifique

    ✅ Utilise check_user_has_role() qui utilise le repository

    Usage:
        @require_role("admin")
        @get("/admin/dashboard")
        async def dashboard(self, request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                logger.warning(f"Unauthenticated access attempt: {request.url.path}")
                return create_unauthorized_response(request)

            # ✅ Utiliser la fonction helper qui utilise le repository
            has_role = await check_user_has_role(request, role_name)

            if not has_role:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} doesn't have role '{role_name}'"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir le rôle '{role_name}' pour accéder à cette page",
                    required_role=role_name,
                )

            user_id = get_current_user_id(request)
            logger.info(f"Access granted: user_id={user_id}, role={role_name}")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_any_role(role_names: List[str]):
    """
    Décorateur : Requiert AU MOINS UN des rôles spécifiés

    ✅ Utilise le repository pour chaque vérification

    Usage:
        @require_any_role(["admin", "moderator"])
        @get("/moderation")
        async def moderation(self, request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ✅ Vérifier chaque rôle avec le repository
            has_any_role = False
            for role in role_names:
                if await check_user_has_role(request, role):
                    has_any_role = True
                    break

            if not has_any_role:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} doesn't have any of roles {role_names}"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir l'un de ces rôles : {', '.join(role_names)}",
                    required_role=", ".join(role_names),
                )

            user_id = get_current_user_id(request)
            logger.info(f"Access granted: user_id={user_id}, has one of {role_names}")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# DÉCORATEURS DE PERMISSIONS
# ==========================================


def require_permission(permission_name: str):
    """
    Décorateur : Requiert une permission spécifique

    ✅ Vérifie permissions directes ET via rôles en utilisant le repository
    ✅ Gère automatiquement les permissions expirées

    Usage:
        @require_permission("user.delete")
        @delete("/users/{user_id}")
        async def delete_user(self, user_id: int, request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ✅ Utiliser la fonction qui utilise le repository
            has_permission = await check_user_has_permission(request, permission_name)

            if not has_permission:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} doesn't have permission '{permission_name}'"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir la permission '{permission_name}' pour accéder à cette page",
                    required_permission=permission_name,
                )

            user_id = get_current_user_id(request)
            logger.info(
                f"Access granted: user_id={user_id}, permission={permission_name}"
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_any_permission(permission_names: List[str]):
    """
    Décorateur : Requiert AU MOINS UNE des permissions spécifiées

    ✅ Vérifie permissions directes ET via rôles en utilisant le repository

    Usage:
        @require_any_permission(["post.edit", "post.delete"])
        @get("/posts/{post_id}/manage")
        async def manage_post(self, post_id: int, request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ✅ Vérifier chaque permission avec le repository
            has_any_permission = False
            for perm in permission_names:
                if await check_user_has_permission(request, perm):
                    has_any_permission = True
                    break

            if not has_any_permission:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} doesn't have any of permissions {permission_names}"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir l'une de ces permissions : {', '.join(permission_names)}",
                    required_permission=", ".join(permission_names),
                )

            user_id = get_current_user_id(request)
            logger.info(
                f"Access granted: user_id={user_id}, has one of {permission_names}"
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


def require_all_permissions(permission_names: List[str]):
    """
    Décorateur : Requiert TOUTES les permissions spécifiées

    ✅ Vérifie permissions directes ET via rôles en utilisant le repository

    Usage:
        @require_all_permissions(["user.update", "user.delete"])
        @post("/users/{user_id}/full-manage")
        async def full_manage_user(self, user_id: int, request: Request):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ✅ Vérifier chaque permission avec le repository
            has_all_permissions = True
            for perm in permission_names:
                if not await check_user_has_permission(request, perm):
                    has_all_permissions = False
                    break

            if not has_all_permissions:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} doesn't have all permissions {permission_names}"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir toutes ces permissions : {', '.join(permission_names)}",
                    required_permission=", ".join(permission_names),
                )

            user_id = get_current_user_id(request)
            logger.info(
                f"Access granted: user_id={user_id}, has all {permission_names}"
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# DÉCORATEUR COMBINÉ
# ==========================================


def require_role_or_permission(role_name: str, permission_name: str):
    """
    Décorateur : Requiert un rôle OU une permission

    ✅ La permission peut être directe OU via rôle (géré par le repository)

    Usage:
        @require_role_or_permission("admin", "post.publish")
        @post("/posts/{post_id}/publish")
        async def publish_post(self, post_id: int, request: Request):
            '''Accessible aux admins OU à ceux qui ont post.publish'''
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ✅ Utiliser les fonctions repository
            has_role = await check_user_has_role(request, role_name)
            has_permission = await check_user_has_permission(request, permission_name)

            has_access = has_role or has_permission

            if not has_access:
                user_id = get_current_user_id(request)
                logger.warning(
                    f"Access denied: user_id={user_id} has neither role '{role_name}' "
                    f"nor permission '{permission_name}'"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir le rôle '{role_name}' ou la permission '{permission_name}'",
                    required_role=role_name,
                    required_permission=permission_name,
                )

            user_id = get_current_user_id(request)
            logger.info(f"Access granted: user_id={user_id}")

            return await func(*args, **kwargs)

        return wrapper

    return decorator


# ==========================================
# DÉCORATEUR PERMISSION DIRECTE UNIQUEMENT
# ==========================================


def require_direct_permission(permission_name: str):
    """
    Décorateur : Requiert une permission DIRECTE (pas via rôle)

    ⚠️ Ce décorateur nécessite toujours de charger le user complet
    car on doit vérifier la relation direct_permissions

    Usage:
        @require_direct_permission("emergency.access")
        @get("/emergency/shutdown")
        async def emergency_shutdown(self, request: Request):
            '''Seulement ceux avec permission directe emergency.access'''
            ...
    """

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            request = None
            for arg in args:
                if isinstance(arg, Request):
                    request = arg
                    break

            if not request:
                request = kwargs.get("request")

            if not request:
                raise ValueError("Request object not found")

            if not is_authenticated(request):
                return create_unauthorized_response(request)

            # ⚠️ Pour les permissions directes, on doit charger l'utilisateur
            user = await get_user_with_rbac(request)

            if not user:
                return create_unauthorized_response(request)

            # Vérifier uniquement les permissions directes
            has_direct = any(
                perm.name == permission_name for perm in user.direct_permissions
            )

            if not has_direct:
                logger.warning(
                    f"Access denied: user_id={user.id} doesn't have DIRECT permission '{permission_name}'"
                )
                return create_forbidden_response(
                    request,
                    message=f"Vous devez avoir la permission directe '{permission_name}'",
                    required_permission=permission_name,
                )

            logger.info(
                f"Access granted: user_id={user.id}, direct_permission={permission_name}"
            )

            return await func(*args, **kwargs)

        return wrapper

    return decorator
