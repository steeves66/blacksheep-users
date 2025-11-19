"""
UserRepository - Couche d'accès aux données

Centralise toutes les opérations sur la base de données :
- CRUD utilisateurs
- CRUD tokens de vérification
- Opérations utilitaires (nettoyage, activation, etc.)

Avantages :
- Découplage : le service n'a pas de dépendance SQLAlchemy directe
- Testabilité : facile de mocker ce repository dans les tests
- Réutilisabilité : ces méthodes peuvent être utilisées par plusieurs services
- Maintenance : changement de DB sans toucher aux services
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import and_, select, delete, func
from sqlalchemy.orm import selectinload
import logging

from app.settings import Settings
from model.user import (
    User,
    EmailVerificationToken,
    PasswordResetToken,
    Role,
    Permission,
    user_permissions,
    user_roles,
    role_permissions,
)


logger = logging.getLogger(__name__)


class UserRepository:
    """Repository pour gérer les utilisateurs et tokens de vérification"""

    def __init__(self, db: AsyncSession, settings: Settings):
        """
        Initialise le repository avec une session de base de données

        Args:
            db: Session SQLAlchemy active
        """
        self.db = db
        self.settings = settings

    # ==========================================
    # OPÉRATIONS SUR LES UTILISATEURS
    # ==========================================

    async def create_user(
        self,
        email: str,
        username: str,
        hashed_password: str,
        is_active: bool = False,
    ) -> User:
        """
        Créer un nouvel utilisateur

        Note : Le mot de passe doit déjà être hashé avant l'appel

        Args:
            email: Email unique de l'utilisateur
            hashed_password: Mot de passe déjà hashé (bcrypt)
            first_name: Prénom (optionnel)
            last_name: Nom (optionnel)
            is_active: Statut initial (False pour inscription avec email)

        Returns:
            Instance User créée et persistée
        """
        user = User(
            email=email,
            username=username,
            password=hashed_password,
            is_active=is_active,
        )

        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)  # Récupère l'ID auto-généré

        logger.info(f"User created: id={user.id}, email={email}, is_active={is_active}")
        return user

    async def get_user_by_id(self, user_id: int) -> Optional[User]:
        """
        Récupérer un utilisateur par son ID
        """
        result = await self.db.execute(select(User).filter(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """
        Récupérer un utilisateur par son email
        """
        result = await self.db.execute(select(User).filter(User.email == email))
        return result.scalar_one_or_none()

    async def user_exists(self, email: str) -> bool:
        """
        Vérifier si un utilisateur avec cet email existe déjà
        """
        result = await self.db.execute(
            select(func.count()).select_from(User).filter(User.email == email)
        )
        count = result.scalar()
        return count > 0

    async def activate_user(self, user_id: int) -> Optional[User]:
        """
        Activer le compte d'un utilisateur
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot activate user: user_id={user_id} not found")
            return None

        user.is_active = True
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"User activated: id={user.id}, email={user.email}")
        return user

    async def deactivate_user(self, user_id: int) -> Optional[User]:
        """
        Désactiver le compte d'un utilisateur
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot deactivate user: user_id={user_id} not found")
            return None

        user.is_active = False
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"User deactivated: id={user.id}, email={user.email}")
        return user

    async def delete_user(self, user_id: int) -> bool:
        """
        Supprimer un utilisateur (hard delete)
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            return False

        await self.db.delete(user)
        await self.db.commit()

        logger.info(f"User deleted: id={user_id}")
        return True

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """
        Récupérer un utilisateur par son nom d'utilisateur
        """
        result = await self.db.execute(select(User).filter(User.username == username))
        return result.scalar_one_or_none()

    # ============================================================
    # OPÉRATIONS SUR LES TOKENS DE REGISTER WITH EMAILVÉRIFICATION
    # ============================================================

    async def create_verification_token(
        self, user_id: int, token: str, expiry_delay: int = 24
    ) -> EmailVerificationToken:
        """
        Créer un token de vérification pour un utilisateur

        Args:
            user_id: ID de l'utilisateur
            token: Token aléatoire généré (secrets.token_urlsafe)
            expiry_hours: Nombre d'heures avant expiration (défaut: 24h)

        Returns:
            Instance EmailVerificationToken créée
        """
        # Calculer la date d'expiration
        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=self.settings.verification.token_expiry_delay
        )

        token_record = EmailVerificationToken(
            user_id=user_id, token=token, expires_at=expires_at, is_used=False
        )

        self.db.add(token_record)
        await self.db.commit()
        await self.db.refresh(token_record)

        logger.info(
            f"Verification token created: user_id={user_id}, expires_at={expires_at}"
        )
        return token_record

    async def get_verification_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[EmailVerificationToken]:
        """
        Récupérer un token de vérification

        Args:
            user_id: ID de l'utilisateur
            token: Token à rechercher
            only_valid: Si True, ne retourne que les tokens valides (non utilisés, non expirés)

        Returns:
            EmailVerificationToken ou None si non trouvé
        """
        # Construire la requête de base
        query = select(EmailVerificationToken).filter(
            and_(
                EmailVerificationToken.user_id == user_id,
                EmailVerificationToken.token == token,
            )
        )

        # Filtrer pour ne garder que les tokens valides si demandé
        if only_valid:
            query = query.filter(
                and_(
                    EmailVerificationToken.is_used == False,
                    EmailVerificationToken.expires_at > datetime.now(timezone.utc),
                )
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_token_as_used(self, token_id: int) -> bool:
        """
        Marquer un token comme utilisé (empêche la réutilisation)
        """
        result = await self.db.execute(
            select(EmailVerificationToken).filter(EmailVerificationToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if not token:
            return False

        token.is_used = True
        await self.db.commit()

        logger.info(f"Token marked as used: id={token_id}, user_id={token.user_id}")
        return True

    async def delete_expired_tokens(self) -> int:
        """
        Supprimer tous les tokens expirés (tâche de nettoyage)

        À exécuter régulièrement (CRON job quotidien recommandé)

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            delete(EmailVerificationToken).filter(
                EmailVerificationToken.expires_at < datetime.now(timezone.utc)
            )
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} expired tokens")
        return count

    async def delete_user_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens d'un utilisateur

        Utilisé pour :
        - Renvoyer un nouvel email (supprimer les anciens tokens)
        - Nettoyage après activation

        Args:
            user_id: ID de l'utilisateur

        Returns:
            Nombre de tokens supprimés
        """
        result = await self.db.execute(
            delete(EmailVerificationToken).filter(
                EmailVerificationToken.user_id == user_id
            )
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} tokens for user_id={user_id}")
        return count

    # ==========================================
    # OPÉRATIONS SUR LES TOKENS DE RESET PASSWORD
    # ==========================================

    async def create_password_reset_token(
        self, user_id: int, token: str, expiry_hours: int = 1
    ) -> PasswordResetToken:
        """
        Créer un token de réinitialisation de mot de passe

        Args:
            user_id: ID de l'utilisateur
            token: Token aléatoire généré (secrets.token_urlsafe)
            expiry_hours: Nombre d'heures avant expiration (défaut: 1h)

        Returns:
            Instance PasswordResetToken créée
        """
        expires_at = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)

        token_record = PasswordResetToken(
            user_id=user_id, token=token, expires_at=expires_at, is_used=False
        )

        self.db.add(token_record)
        await self.db.commit()
        await self.db.refresh(token_record)

        logger.info(
            f"Password reset token created: user_id={user_id}, expires_at={expires_at}"
        )
        return token_record

    async def get_password_reset_token(
        self, user_id: int, token: str, only_valid: bool = True
    ) -> Optional[PasswordResetToken]:
        """
        Récupérer un token de réinitialisation de mot de passe

        Args:
            user_id: ID de l'utilisateur
            token: Token à rechercher
            only_valid: Si True, ne retourne que les tokens valides

        Returns:
            PasswordResetToken ou None
        """
        query = select(PasswordResetToken).filter(
            and_(
                PasswordResetToken.user_id == user_id,
                PasswordResetToken.token == token,
            )
        )

        if only_valid:
            query = query.filter(
                and_(
                    PasswordResetToken.is_used == False,
                    PasswordResetToken.expires_at > datetime.now(timezone.utc),
                )
            )

        result = await self.db.execute(query)
        return result.scalar_one_or_none()

    async def mark_password_reset_token_as_used(self, token_id: int) -> bool:
        """Marquer un token de reset comme utilisé"""
        result = await self.db.execute(
            select(PasswordResetToken).filter(PasswordResetToken.id == token_id)
        )
        token = result.scalar_one_or_none()

        if not token:
            return False

        token.is_used = True
        await self.db.commit()

        logger.info(
            f"Password reset token marked as used: id={token_id}, user_id={token.user_id}"
        )
        return True

    async def delete_user_password_reset_tokens(self, user_id: int) -> int:
        """
        Supprimer tous les tokens de reset d'un utilisateur

        Utilisé pour:
        - Nettoyer avant de créer un nouveau token
        - Invalider tous les tokens après un reset réussi
        """
        result = await self.db.execute(
            delete(PasswordResetToken).filter(PasswordResetToken.user_id == user_id)
        )

        await self.db.commit()

        count = result.rowcount
        logger.info(f"Deleted {count} password reset tokens for user_id={user_id}")
        return count

    async def update_user_password(
        self, user_id: int, hashed_password: str
    ) -> Optional[User]:
        """
        Mettre à jour le mot de passe d'un utilisateur

        Args:
            user_id: ID de l'utilisateur
            hashed_password: Nouveau mot de passe hashé

        Returns:
            User mis à jour ou None
        """
        user = await self.get_user_by_id(user_id)

        if not user:
            logger.warning(f"Cannot update password: user_id={user_id} not found")
            return None

        user.password = hashed_password
        user.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"Password updated: user_id={user.id}")
        return user

    # ==========================================
    # GESTION DES RÔLES
    # ==========================================

    async def create_role(
        self,
        name: str,
        display_name: str,
        description: Optional[str] = None,
        priority: int = 0,
        is_system: bool = False,
        is_default: bool = False,
    ) -> Role:
        """Créer un nouveau rôle"""
        role = Role(
            name=name,
            display_name=display_name,
            description=description,
            priority=priority,
            is_system=is_system,
            is_default=is_default,
        )

        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)

        logger.info(f"Role created: id={role.id}, name={role.name}")
        return role

    async def get_role_by_id(self, role_id: int) -> Optional[Role]:
        """Récupérer un rôle par son ID"""
        result = await self.db.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .filter(Role.id == role_id)
        )
        return result.scalar_one_or_none()

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Récupérer un rôle par son nom"""
        result = await self.db.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .filter(Role.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_roles(self) -> List[Role]:
        """Récupérer tous les rôles"""
        result = await self.db.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .order_by(Role.priority.desc())
        )
        return result.scalars().all()

    async def get_default_role(self) -> Optional[Role]:
        """Récupérer le rôle par défaut"""
        result = await self.db.execute(select(Role).filter(Role.is_default == True))
        return result.scalar_one_or_none()

    async def update_role(
        self,
        role_id: int,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        priority: Optional[int] = None,
    ) -> Optional[Role]:
        """Mettre à jour un rôle"""
        role = await self.get_role_by_id(role_id)

        if not role:
            return None

        if display_name is not None:
            role.display_name = display_name
        if description is not None:
            role.description = description
        if priority is not None:
            role.priority = priority

        await self.db.commit()
        await self.db.refresh(role)

        logger.info(f"Role updated: id={role.id}, name={role.name}")
        return role

    async def delete_role(self, role_id: int) -> bool:
        """Supprimer un rôle (sauf si is_system=True)"""
        role = await self.get_role_by_id(role_id)

        if not role:
            return False

        if role.is_system:
            logger.warning(f"Cannot delete system role: id={role_id}")
            return False

        await self.db.delete(role)
        await self.db.commit()

        logger.info(f"Role deleted: id={role_id}, name={role.name}")
        return True

    # ==========================================
    # GESTION DES PERMISSIONS
    # ==========================================

    async def create_permission(
        self,
        name: str,
        display_name: str,
        resource: str,
        action: str,
        description: Optional[str] = None,
        is_system: bool = False,
    ) -> Permission:
        """Créer une nouvelle permission"""
        permission = Permission(
            name=name,
            display_name=display_name,
            resource=resource,
            action=action,
            description=description,
            is_system=is_system,
        )

        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)

        logger.info(f"Permission created: id={permission.id}, name={permission.name}")
        return permission

    async def get_permission_by_id(self, permission_id: int) -> Optional[Permission]:
        """Récupérer une permission par son ID"""
        result = await self.db.execute(
            select(Permission).filter(Permission.id == permission_id)
        )
        return result.scalar_one_or_none()

    async def get_permission_by_name(self, name: str) -> Optional[Permission]:
        """Récupérer une permission par son nom"""
        result = await self.db.execute(
            select(Permission).filter(Permission.name == name)
        )
        return result.scalar_one_or_none()

    async def get_all_permissions(self) -> List[Permission]:
        """Récupérer toutes les permissions"""
        result = await self.db.execute(
            select(Permission).order_by(Permission.resource, Permission.action)
        )
        return result.scalars().all()

    async def get_permissions_by_resource(self, resource: str) -> List[Permission]:
        """Récupérer toutes les permissions d'une ressource"""
        result = await self.db.execute(
            select(Permission)
            .filter(Permission.resource == resource)
            .order_by(Permission.action)
        )
        return result.scalars().all()

    async def delete_permission(self, permission_id: int) -> bool:
        """Supprimer une permission (sauf si is_system=True)"""
        permission = await self.get_permission_by_id(permission_id)

        if not permission:
            return False

        if permission.is_system:
            logger.warning(f"Cannot delete system permission: id={permission_id}")
            return False

        await self.db.delete(permission)
        await self.db.commit()

        logger.info(f"Permission deleted: id={permission_id}, name={permission.name}")
        return True

    # ==========================================
    # ATTRIBUTION RÔLE <-> UTILISATEUR
    # ==========================================

    async def assign_role_to_user(
        self, user_id: int, role_id: int, assigned_by: Optional[int] = None
    ) -> bool:
        """Attribuer un rôle à un utilisateur"""
        user = await self.db.get(User, user_id)
        role = await self.get_role_by_id(role_id)

        if not user or not role:
            logger.warning(
                f"User or role not found: user_id={user_id}, role_id={role_id}"
            )
            return False

        # Vérifier si l'association existe déjà
        result = await self.db.execute(
            select(user_roles).where(
                and_(
                    user_roles.c.user_id == user_id,
                    user_roles.c.role_id == role_id,
                )
            )
        )

        if result.first():
            logger.info(f"User already has role: user_id={user_id}, role_id={role_id}")
            return True

        # Créer l'association
        stmt = user_roles.insert().values(
            user_id=user_id,
            role_id=role_id,
            assigned_by=assigned_by,
        )
        await self.db.execute(stmt)
        await self.db.commit()

        logger.info(f"Role assigned: user_id={user_id}, role={role.name}")
        return True

    async def remove_role_from_user(self, user_id: int, role_id: int) -> bool:
        """Retirer un rôle à un utilisateur"""
        stmt = delete(user_roles).where(
            and_(
                user_roles.c.user_id == user_id,
                user_roles.c.role_id == role_id,
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        if result.rowcount > 0:
            logger.info(f"Role removed: user_id={user_id}, role_id={role_id}")
            return True

        return False

    async def assign_default_role_to_user(self, user_id: int) -> bool:
        """Attribuer le rôle par défaut à un utilisateur"""
        default_role = await self.get_default_role()

        if not default_role:
            logger.warning("No default role found")
            return False

        return await self.assign_role_to_user(user_id, default_role.id)

    async def get_user_roles(self, user_id: int) -> List[Role]:
        """Récupérer tous les rôles d'un utilisateur"""
        result = await self.db.execute(
            select(Role)
            .join(user_roles)
            .where(user_roles.c.user_id == user_id)
            .options(selectinload(Role.permissions))
            .order_by(Role.priority.desc())
        )
        return result.scalars().all()

    # ==========================================
    # ATTRIBUTION PERMISSION <-> RÔLE
    # ==========================================

    async def assign_permission_to_role(self, role_id: int, permission_id: int) -> bool:
        """Attribuer une permission à un rôle"""
        role = await self.get_role_by_id(role_id)
        permission = await self.get_permission_by_id(permission_id)

        if not role or not permission:
            logger.warning(
                f"Role or permission not found: role_id={role_id}, permission_id={permission_id}"
            )
            return False

        # Vérifier si l'association existe déjà
        result = await self.db.execute(
            select(role_permissions).where(
                and_(
                    role_permissions.c.role_id == role_id,
                    role_permissions.c.permission_id == permission_id,
                )
            )
        )

        if result.first():
            logger.info(
                f"Role already has permission: role_id={role_id}, permission_id={permission_id}"
            )
            return True

        # Créer l'association
        stmt = role_permissions.insert().values(
            role_id=role_id,
            permission_id=permission_id,
        )
        await self.db.execute(stmt)
        await self.db.commit()

        logger.info(
            f"Permission assigned to role: role={role.name}, permission={permission.name}"
        )
        return True

    async def remove_permission_from_role(
        self, role_id: int, permission_id: int
    ) -> bool:
        """Retirer une permission à un rôle"""
        stmt = delete(role_permissions).where(
            and_(
                role_permissions.c.role_id == role_id,
                role_permissions.c.permission_id == permission_id,
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        if result.rowcount > 0:
            logger.info(
                f"Permission removed from role: role_id={role_id}, permission_id={permission_id}"
            )
            return True

        return False

    async def get_role_permissions(self, role_id: int) -> List[Permission]:
        """Récupérer toutes les permissions d'un rôle"""
        result = await self.db.execute(
            select(Permission)
            .join(role_permissions)
            .where(role_permissions.c.role_id == role_id)
            .order_by(Permission.resource, Permission.action)
        )
        return result.scalars().all()

    # ==========================================
    # ⭐ NOUVEAU : PERMISSIONS DIRECTES UTILISATEUR
    # ==========================================

    async def assign_permission_to_user(
        self,
        user_id: int,
        permission_id: int,
        assigned_by: Optional[int] = None,
        expires_at: Optional[datetime] = None,
        reason: Optional[str] = None,
    ) -> bool:
        """
        Attribuer une permission directe à un utilisateur

        Args:
            user_id: ID de l'utilisateur
            permission_id: ID de la permission
            assigned_by: ID de l'utilisateur qui attribue la permission
            expires_at: Date d'expiration (optionnel) pour permissions temporaires
            reason: Raison de l'attribution (pour audit)

        Returns:
            bool: True si succès
        """
        user = await self.db.get(User, user_id)
        permission = await self.get_permission_by_id(permission_id)

        if not user or not permission:
            logger.warning(
                f"User or permission not found: user_id={user_id}, permission_id={permission_id}"
            )
            return False

        # Vérifier si l'association existe déjà
        result = await self.db.execute(
            select(user_permissions).where(
                and_(
                    user_permissions.c.user_id == user_id,
                    user_permissions.c.permission_id == permission_id,
                )
            )
        )

        if result.first():
            logger.info(
                f"User already has direct permission: user_id={user_id}, permission_id={permission_id}"
            )
            return True

        # Créer l'association
        stmt = user_permissions.insert().values(
            user_id=user_id,
            permission_id=permission_id,
            assigned_by=assigned_by,
            expires_at=expires_at,
            reason=reason,
        )
        await self.db.execute(stmt)
        await self.db.commit()

        logger.info(
            f"Direct permission assigned: user_id={user_id}, permission={permission.name}, "
            f"expires_at={expires_at}, reason={reason}"
        )
        return True

    async def remove_permission_from_user(
        self, user_id: int, permission_id: int
    ) -> bool:
        """Retirer une permission directe d'un utilisateur"""
        stmt = delete(user_permissions).where(
            and_(
                user_permissions.c.user_id == user_id,
                user_permissions.c.permission_id == permission_id,
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        if result.rowcount > 0:
            logger.info(
                f"Direct permission removed: user_id={user_id}, permission_id={permission_id}"
            )
            return True

        return False

    async def get_user_direct_permissions(self, user_id: int) -> List[Permission]:
        """Récupérer uniquement les permissions directes d'un utilisateur"""
        result = await self.db.execute(
            select(Permission)
            .join(user_permissions)
            .where(user_permissions.c.user_id == user_id)
            .order_by(Permission.resource, Permission.action)
        )
        return result.scalars().all()

    async def get_user_direct_permissions_with_details(
        self, user_id: int
    ) -> List[Tuple[Permission, dict]]:
        """
        Récupérer les permissions directes avec détails (expiration, raison)

        Returns:
            List de tuples (Permission, details_dict)
            details_dict contient: assigned_at, assigned_by, expires_at, reason
        """
        result = await self.db.execute(
            select(
                Permission,
                user_permissions.c.assigned_at,
                user_permissions.c.assigned_by,
                user_permissions.c.expires_at,
                user_permissions.c.reason,
            )
            .join(user_permissions, Permission.id == user_permissions.c.permission_id)
            .where(user_permissions.c.user_id == user_id)
            .order_by(Permission.resource, Permission.action)
        )

        return [
            (
                perm,
                {
                    "assigned_at": assigned_at,
                    "assigned_by": assigned_by,
                    "expires_at": expires_at,
                    "reason": reason,
                },
            )
            for perm, assigned_at, assigned_by, expires_at, reason in result.fetchall()
        ]

    async def cleanup_expired_permissions(self) -> int:
        """
        Nettoyer les permissions directes expirées

        À exécuter régulièrement (CRON job recommandé)

        Returns:
            Nombre de permissions supprimées
        """
        stmt = delete(user_permissions).where(
            and_(
                user_permissions.c.expires_at.isnot(None),
                user_permissions.c.expires_at < datetime.now(timezone.utc),
            )
        )
        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        logger.info(f"Cleaned up {count} expired direct permissions")
        return count

    # ==========================================
    # VÉRIFICATIONS
    # ==========================================

    async def user_has_role(self, user_id: int, role_name: str) -> bool:
        """Vérifier si un utilisateur a un rôle spécifique"""
        result = await self.db.execute(
            select(func.count())
            .select_from(user_roles)
            .join(Role)
            .where(
                and_(
                    user_roles.c.user_id == user_id,
                    Role.name == role_name,
                )
            )
        )
        count = result.scalar()
        return count > 0

    async def user_has_permission(self, user_id: int, permission_name: str) -> bool:
        """
        Vérifier si un utilisateur a une permission (via rôle OU directe)

        Vérifie :
        1. Permissions directes (user_permissions)
        2. Permissions via rôles (role_permissions)
        """
        # 1. Vérifier permissions directes
        result_direct = await self.db.execute(
            select(func.count())
            .select_from(user_permissions)
            .join(Permission)
            .where(
                and_(
                    user_permissions.c.user_id == user_id,
                    Permission.name == permission_name,
                    # Exclure les permissions expirées
                    (
                        user_permissions.c.expires_at.is_(None)
                        | (user_permissions.c.expires_at > datetime.now(timezone.utc))
                    ),
                )
            )
        )

        if result_direct.scalar() > 0:
            return True

        # 2. Vérifier permissions via rôles
        result_role = await self.db.execute(
            select(func.count())
            .select_from(user_roles)
            .join(role_permissions, user_roles.c.role_id == role_permissions.c.role_id)
            .join(Permission)
            .where(
                and_(
                    user_roles.c.user_id == user_id,
                    Permission.name == permission_name,
                )
            )
        )

        return result_role.scalar() > 0

    async def get_user_all_permissions(self, user_id: int) -> List[str]:
        """
        Récupérer toutes les permissions d'un utilisateur (directes + rôles)

        Returns:
            Liste de noms de permissions (dédupliqués)
        """
        permissions = set()

        # 1. Permissions directes
        direct_perms = await self.get_user_direct_permissions(user_id)
        for perm in direct_perms:
            permissions.add(perm.name)

        # 2. Permissions via rôles
        roles = await self.get_user_roles(user_id)
        for role in roles:
            role_perms = await self.get_role_permissions(role.id)
            for perm in role_perms:
                permissions.add(perm.name)

        return sorted(list(permissions))

    # ==========================================
    # STATISTIQUES
    # ==========================================

    async def get_role_user_count(self, role_id: int) -> int:
        """Compter le nombre d'utilisateurs ayant un rôle"""
        result = await self.db.execute(
            select(func.count())
            .select_from(user_roles)
            .where(user_roles.c.role_id == role_id)
        )
        return result.scalar()

    async def get_permission_role_count(self, permission_id: int) -> int:
        """Compter le nombre de rôles ayant une permission"""
        result = await self.db.execute(
            select(func.count())
            .select_from(role_permissions)
            .where(role_permissions.c.permission_id == permission_id)
        )
        return result.scalar()

    async def get_permission_direct_user_count(self, permission_id: int) -> int:
        """Compter le nombre d'utilisateurs ayant une permission directe"""
        result = await self.db.execute(
            select(func.count())
            .select_from(user_permissions)
            .where(user_permissions.c.permission_id == permission_id)
        )
        return result.scalar()
