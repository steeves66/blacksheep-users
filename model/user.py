"""
Modèle User - Représente un utilisateur dans le système

Champs principaux :
- email : identifiant unique de l'utilisateur
- password : mot de passe hashé (jamais en clair)
- is_active : False par défaut, True après vérification email
- is_superuser : pour les droits administrateur
- dates : suivi de création et modification
"""

from datetime import datetime, UTC, timedelta
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    JSON,
)
from sqlalchemy.orm import relationship

from model.base import Base


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
        return datetime.now(UTC) > self.expires_at

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


"""
Modèle pour le Rate Limiting - Limite les requêtes par utilisateur
"""


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
