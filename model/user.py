"""
Modèle User - Représente un utilisateur dans le système

Champs principaux :
- email : identifiant unique de l'utilisateur
- password : mot de passe hashé (jamais en clair)
- is_active : False par défaut, True après vérification email
- is_superuser : pour les droits administrateur
- dates : suivi de création et modification
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from model.base import Base

# model for RABC functionality
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    ),
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    ),
    Column("assigned_at", DateTime, default=lambda: datetime.now(UTC)),
    Column(
        "assigned_by",
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    ),
    UniqueConstraint("user_id", "role_id", name="uq_user_role"),
)

# Table de liaison Role <-> Permission
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    ),
    Column(
        "permission_id",
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("assigned_at", DateTime, default=lambda: datetime.now(UTC)),
    UniqueConstraint("role_id", "permission_id", name="uq_role_permission"),
)

# ⭐ NOUVEAU : Table de liaison User <-> Permission (permissions directes)
user_permissions = Table(
    "user_permissions",
    Base.metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column(
        "user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    ),
    Column(
        "permission_id",
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("assigned_at", DateTime, default=lambda: datetime.now(UTC)),
    Column(
        "assigned_by",
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    ),
    Column("expires_at", DateTime, nullable=True),  # Permission temporaire (optionnel)
    Column("reason", Text, nullable=True),  # Raison de l'attribution (audit)
    UniqueConstraint("user_id", "permission_id", name="uq_user_permission"),
)


class User(Base):
    """Modèle utilisateur avec système de vérification email"""

    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(255), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # ✅ CORRECTION : Utiliser lambda pour appeler datetime.now(UTC)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # ✅ Relation avec les sessions (User → Session)
    sessions = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",  # Supprimer les sessions si user supprimé
    )

    # Relations RBAC
    roles = relationship(
        "Role",
        secondary=user_roles,
        back_populates="users",
        lazy="selectin",
        foreign_keys=[user_roles.c.user_id, user_roles.c.role_id],
    )

    # ⭐ NOUVEAU : Permissions directes
    direct_permissions = relationship(
        "Permission",
        secondary=user_permissions,
        back_populates="users",
        lazy="selectin",
        foreign_keys=[user_permissions.c.user_id, user_permissions.c.permission_id],
    )

    def __repr__(self):
        return f"<User(id={self.id}, email='{self.email}', is_active={self.is_active})>"

    def to_dict(self):
        """Convertir en dictionnaire (pour les réponses API)"""
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "is_active": self.is_active,
            "is_superuser": self.is_superuser,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    # ==========================================
    # MÉTHODES RBAC
    # ==========================================

    def has_role(self, role_name: str) -> bool:
        """Vérifie si l'utilisateur a un rôle spécifique"""
        return any(role.name == role_name for role in self.roles)

    def has_permission(self, permission_name: str) -> bool:
        """
        Vérifie si l'utilisateur a une permission spécifique

        Recherche dans :
        1. Les permissions directes de l'utilisateur (user_permissions)
        2. Les permissions héritées des rôles de l'utilisateur

        Returns:
            True si l'utilisateur a la permission (directe ou via un rôle)
        """
        # 1. Vérifier les permissions directes
        for permission in self.direct_permissions:
            if permission.name == permission_name:
                # Vérifier l'expiration si applicable
                if hasattr(permission, "expires_at") and permission.expires_at:
                    if permission.expires_at < datetime.now(UTC):
                        continue  # Permission expirée
                return True

        # 2. Vérifier les permissions via les rôles
        for role in self.roles:
            if role.has_permission(permission_name):
                return True

        return False

    def get_highest_role(self):
        """Retourne le rôle avec la priorité la plus élevée"""
        if not self.roles:
            return None
        return max(self.roles, key=lambda r: r.priority)

    def get_all_permissions(self) -> set:
        """
        Retourne toutes les permissions de l'utilisateur

        Combine :
        - Les permissions directes (user_permissions)
        - Les permissions héritées des rôles

        Returns:
            Set de noms de permissions (dédupliqué)
        """
        permissions = set()

        # Permissions directes
        for perm in self.direct_permissions:
            # Vérifier l'expiration
            if hasattr(perm, "expires_at") and perm.expires_at:
                if perm.expires_at < datetime.now(UTC):
                    continue  # Permission expirée
            permissions.add(perm.name)

        # Permissions via rôles
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.name)

        return permissions

    def get_direct_permissions(self) -> list:
        """Retourne uniquement les permissions directes (sans celles des rôles)"""
        return [perm.name for perm in self.direct_permissions]

    def get_role_permissions(self) -> set:
        """Retourne uniquement les permissions héritées des rôles"""
        permissions = set()
        for role in self.roles:
            for perm in role.permissions:
                permissions.add(perm.name)
        return permissions


# Functionality for register with email verification
class EmailVerificationToken(Base):
    """
    Token de vérification email avec expiration et suivi d'utilisation

    Sécurité : Le token est stocké en base ET signé avec itsdangerous
    - Base : permet de vérifier que le token existe et n'est pas réutilisé
    - Signature : garantit que le token n'a pas été modifié
    """

    __tablename__ = "email_verification_tokens"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token = Column(String(255), unique=True, index=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)

    # Relation avec User (permet d'accéder à user.verification_tokens)
    user = relationship("User", backref="verification_tokens")

    def __repr__(self):
        return f"<EmailVerificationToken(id={self.id}, user_id={self.user_id}, is_used={self.is_used})>"

    def is_expired(self) -> bool:
        """Vérifie si le token a expiré"""
        # ✅ CORRECTION : Retirer le double appel de fonction ()
        return datetime.now(UTC) > self.expires_at

    def is_valid(self) -> bool:
        """Vérifie si le token est valide (non utilisé ET non expiré)"""
        return not self.is_used and not self.is_expired()


# Functionality for reset password with email
class PasswordResetToken(Base):
    """
    Token de réinitialisation de mot de passe avec expiration et suivi d'utilisation

    Sécurité : Le token est stocké en base ET signé avec itsdangerous
    - Base : permet de vérifier que le token existe et n'est pas réutilisé
    - Signature : garantit que le token n'a pas été modifié
    """

    __tablename__ = "password_reset_tokens"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token = Column(String(255), unique=True, index=True, nullable=False)
    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)

    # Relation avec User
    user = relationship("User", backref="password_reset_tokens")

    def __repr__(self):
        return f"<PasswordResetToken(id={self.id}, user_id={self.user_id}, is_used={self.is_used})>"

    def is_expired(self) -> bool:
        """Vérifie si le token a expiré"""
        return datetime.now(UTC) > self.expires_at

    def is_valid(self) -> bool:
        """Vérifie si le token est valide (non utilisé ET non expiré)"""
        return not self.is_used and not self.is_expired()


# Functionality for session management
class Session(Base):
    """
    Modèle de session pour stockage en base de données.

    Supporte :
    - Sessions anonymes (user_id = NULL)
    - Sessions authentifiées (user_id = ID utilisateur)
    """

    __tablename__ = "sessions"

    # Clé primaire : ID de session (token)
    id = Column(String(64), primary_key=True)

    # Lien utilisateur (NULL = session anonyme)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # Données de session (JSON sérialisé)
    data = Column(JSON, nullable=False, default=dict)

    # Métadonnées temporelles
    created_at = Column(DateTime, nullable=False)
    last_accessed = Column(DateTime, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)

    # Sécurité : tracking client
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)

    # Index composites pour performances
    __table_args__ = (
        Index("idx_user_expires", "user_id", "expires_at"),
        Index("idx_last_accessed", "last_accessed"),
    )

    # ✅ CORRECTION : Relation avec User (Session → User), pas Session → Session !
    user = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        user_info = f"user={self.user_id}" if self.user_id else "anonymous"
        return f"<Session {self.id[:8]}... {user_info}>"

    def is_expired(self) -> bool:
        """Vérifie si la session est expirée"""
        expires_at = self.expires_at
        if expires_at.tzinfo is None:
            # Si naive, on suppose UTC
            expires_at = expires_at.replace(tzinfo=UTC)
        return datetime.now(UTC) > expires_at

    def extend_expiration(self, seconds: int = 3600) -> None:
        """
        Prolonge la durée de vie de la session.

        Args:
            seconds: Nombre de secondes à ajouter (défaut: 3600 = 1h)
        """
        self.expires_at = datetime.now(UTC) + timedelta(seconds=seconds)

    def to_dict(self) -> dict:
        """Convertit la session en dictionnaire."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_accessed": self.last_accessed.isoformat()
            if self.last_accessed
            else None,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "is_expired": self.is_expired(),
        }


# Modèle pour le Rate Limiting - Limite les requêtes par utilisateur
class RateLimit(Base):
    """
    Suivi des requêtes pour le rate limiting

    Chaque entrée représente une tentative de requête.
    On compte les tentatives dans une fenêtre de temps pour limiter les abus.
    """

    __tablename__ = "rate_limits"

    id = Column(Integer, primary_key=True, index=True)

    # Identifiant unique (IP + endpoint ou user_id + endpoint)
    identifier = Column(String(255), nullable=False, index=True)

    # Endpoint concerné (ex: "/users/register", "/users/login")
    endpoint = Column(String(255), nullable=False)

    # Timestamp de la tentative
    attempted_at = Column(
        DateTime, default=lambda: datetime.now(UTC), nullable=False, index=True
    )

    # Informations additionnelles
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)

    # Index composites pour performances
    __table_args__ = (
        Index("idx_identifier_endpoint_time", "identifier", "endpoint", "attempted_at"),
        Index("idx_endpoint_time", "endpoint", "attempted_at"),
    )

    def __repr__(self):
        return f"<RateLimit(id={self.id}, identifier='{self.identifier}', endpoint='{self.endpoint}')>"


# ==========================================
# MODÈLE ROLE
# ==========================================


class Role(Base):
    """
    Modèle pour les rôles utilisateurs

    Exemples de rôles :
    - super_admin : Accès complet au système
    - admin : Administration générale
    - moderator : Modération du contenu
    - user : Utilisateur standard
    - guest : Utilisateur invité (lecture seule)
    """

    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Nom du rôle (unique, slug-friendly)
    name = Column(String(50), unique=True, nullable=False, index=True)

    # Nom d'affichage
    display_name = Column(String(100), nullable=False)

    # Description du rôle
    description = Column(Text, nullable=True)

    # Rôle système (ne peut pas être supprimé)
    is_system = Column(Boolean, default=False, nullable=False)

    # Rôle par défaut (assigné automatiquement aux nouveaux utilisateurs)
    is_default = Column(Boolean, default=False, nullable=False)

    # Priorité/Niveau du rôle (plus le nombre est élevé, plus le rôle est important)
    priority = Column(Integer, default=0, nullable=False, index=True)

    # Métadonnées
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relations
    permissions = relationship(
        "Permission",
        secondary=role_permissions,
        back_populates="roles",
        lazy="selectin",
        foreign_keys=[role_permissions.c.role_id, role_permissions.c.permission_id],
    )

    users = relationship(
        "User",
        secondary=user_roles,
        back_populates="roles",
        lazy="dynamic",
        foreign_keys=[user_roles.c.user_id, user_roles.c.role_id],
    )

    def __repr__(self):
        return f"<Role(id={self.id}, name='{self.name}', priority={self.priority})>"

    def has_permission(self, permission_name: str) -> bool:
        """Vérifie si ce rôle a une permission spécifique"""
        return any(perm.name == permission_name for perm in self.permissions)


# ==========================================
# MODÈLE PERMISSION
# ==========================================


class Permission(Base):
    """
    Modèle pour les permissions

    Convention de nommage : resource.action
    Exemples :
    - user.create, user.read, user.update, user.delete
    - post.publish
    - comment.moderate
    - settings.manage
    """

    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True, autoincrement=True)

    # Nom de la permission (unique, format : resource.action)
    name = Column(String(100), unique=True, nullable=False, index=True)

    # Nom d'affichage
    display_name = Column(String(100), nullable=False)

    # Description
    description = Column(Text, nullable=True)

    # Catégorie/Ressource (pour regrouper dans l'UI)
    resource = Column(String(50), nullable=False, index=True)

    # Action
    action = Column(String(50), nullable=False)

    # Permission système (ne peut pas être supprimée)
    is_system = Column(Boolean, default=False, nullable=False)

    # Métadonnées
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    # Relations
    roles = relationship(
        "Role", secondary=role_permissions, back_populates="permissions", lazy="dynamic"
    )

    # ⭐ NOUVEAU : Relation avec les utilisateurs (permissions directes)
    users = relationship(
        "User",
        secondary=user_permissions,
        back_populates="direct_permissions",
        lazy="dynamic",
        foreign_keys=[user_permissions.c.user_id, user_permissions.c.permission_id],
    )

    def __repr__(self):
        return f"<Permission(id={self.id}, name='{self.name}')>"
