"""
Modèle User - Représente un utilisateur dans le système

Champs principaux :
- email : identifiant unique de l'utilisateur
- password : mot de passe hashé (jamais en clair)
- is_active : False par défaut, True après vérification email
- is_superuser : pour les droits administrateur
- dates : suivi de création et modification
"""

from typing import Optional
from datetime import datetime, timedelta, UTC
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Index, JSON
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
    created_at = Column(DateTime, default=datetime.now(UTC), nullable=False)
    updated_at = Column(
        DateTime, default=datetime.now(UTC), onupdate=datetime.now(UTC), nullable=False
    )

    # ✅ Relation avec les sessions
    sessions = relationship(
        "SessionModel",
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
            "is_active": self.is_active,
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
    created_at = Column(DateTime, default=datetime.now(UTC), nullable=False)

    # Relation avec User (permet d'accéder à user.verification_tokens)
    user = relationship("User", backref="verification_tokens")
 
    def __repr__(self):
        return f"<EmailVerificationToken(id={self.id}, user_id={self.user_id}, is_used={self.is_used})>"

    def is_expired(self) -> bool:
        """Vérifie si le token a expiré"""
        return datetime.now(UTC)() > self.expires_at

    def is_valid(self) -> bool:
        """Vérifie si le token est valide (non utilisé ET non expiré)"""
        return not self.is_used and not self.is_expired()


class SessionModel(Base):
    """
    Modèle de session avec support utilisateur.
    
    Champs :
    - id : Identifiant unique de session (token)
    - user_id : ID de l'utilisateur (NULL pour sessions anonymes)
    - data : Données JSON de la session
    - created_at : Date de création
    - last_accessed : Dernier accès (mis à jour à chaque requête)
    - expires_at : Date d'expiration
    - ip_address : Adresse IP du client
    - user_agent : User-Agent du navigateur
    """
    
    __tablename__ = "sessions"

    id = Column(String(64), primary_key=True, index=True)
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),  # Suppression en cascade
        nullable=True,  # NULL = session anonyme
        index=True,  # Index pour requêtes rapides
    )
    
    # Données de session (JSON sérialisé)
    data = Column(JSON, nullable=False, default="{}")
    
    # Horodatages
    created_at = Column(DateTime, nullable=False, default=datetime.now(UTC))
    last_accessed = Column(
        DateTime, 
        nullable=False, 
        default=datetime.now(UTC),
        onupdate=datetime.now(UTC),
        index=True,  # Index pour cleanup des sessions inactives
    )
    expires_at = Column(
        DateTime, 
        nullable=False,
        index=True,  # Index pour cleanup des sessions expirées
    )
    
    # Sécurité : Tracking
    ip_address = Column(String(45), nullable=True)  # IPv6 = max 45 chars
    user_agent = Column(String(255), nullable=True)

    # ========================================================================
    # Relations
    # ========================================================================
    
    # ✅ NOUVEAU : Relation avec User
    user = relationship(
        "User",
        back_populates="sessions",
        lazy="joined",  # Chargement automatique pour éviter N+1 queries
    )

    # ========================================================================
    # Index composites pour optimiser les requêtes
    # ========================================================================
    
    __table_args__ = (
        # Index pour trouver toutes les sessions d'un utilisateur
        Index("idx_user_expires", "user_id", "expires_at"),
        
        # Index pour cleanup des sessions expirées
        Index("idx_expires_at", "expires_at"),
        
        # Index pour requêtes de sécurité (IP + User-Agent)
        Index("idx_security", "ip_address", "user_agent"),
    )

    # ========================================================================
    # Méthodes utilitaires
    # ========================================================================
    
    def is_expired(self) -> bool:
        """Vérifie si la session est expirée."""
        return self.expires_at < datetime.now(UTC)()
    
    def is_authenticated(self) -> bool:
        """Vérifie si la session est liée à un utilisateur."""
        return self.user_id is not None
    
    def __repr__(self) -> str:
        user_info = f"user={self.user_id}" if self.user_id else "anonymous"
        return f"<Session id={self.id[:8]}... {user_info} expires={self.expires_at}>"

