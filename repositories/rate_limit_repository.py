"""
RateLimitRepository - Couche d'accès aux données pour le rate limiting

Centralise toutes les opérations sur les tentatives de requêtes :
- Enregistrement des tentatives
- Comptage dans une fenêtre de temps
- Nettoyage des anciennes entrées
- Statistiques et monitoring

Avantages :
- Découplage : séparation des préoccupations
- Testabilité : facile de mocker
- Réutilisabilité : utilisable par plusieurs décorateurs/services
- Maintenance : changements DB sans toucher à la logique métier
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

from sqlalchemy import and_, delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from model.user import RateLimit

logger = logging.getLogger(__name__)


class RateLimitRepository:
    """Repository pour gérer les tentatives de requêtes et le rate limiting"""

    def __init__(self, db: AsyncSession):
        """
        Initialise le repository avec une session de base de données

        Args:
            db: Session SQLAlchemy active
        """
        self.db = db

    # ==========================================
    # ENREGISTREMENT DES TENTATIVES
    # ==========================================

    async def record_attempt(
        self,
        identifier: str,
        endpoint: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> RateLimit:
        """
        Enregistrer une tentative de requête

        Args:
            identifier: Identifiant unique (ip:xxx ou user:xxx)
            endpoint: Endpoint concerné (ex: "/users/register")
            ip_address: Adresse IP du client
            user_agent: User agent du client

        Returns:
            Instance RateLimit créée
        """
        rate_entry = RateLimit(
            identifier=identifier,
            endpoint=endpoint,
            ip_address=ip_address,
            user_agent=user_agent[:500] if user_agent else None,  # Limite à 500 caractères
        )

        self.db.add(rate_entry)
        await self.db.commit()
        await self.db.refresh(rate_entry)

        logger.debug(
            f"Rate limit attempt recorded: identifier={identifier}, "
            f"endpoint={endpoint}, ip={ip_address}"
        )

        return rate_entry

    # ==========================================
    # COMPTAGE DES TENTATIVES
    # ==========================================

    async def count_attempts(
        self,
        identifier: str,
        endpoint: str,
        window_seconds: int,
    ) -> int:
        """
        Compter les tentatives dans une fenêtre de temps

        Args:
            identifier: Identifiant unique (ip:xxx ou user:xxx)
            endpoint: Endpoint concerné
            window_seconds: Taille de la fenêtre en secondes

        Returns:
            Nombre de tentatives dans la fenêtre
        """
        window_start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

        stmt = (
            select(func.count(RateLimit.id))
            .where(RateLimit.identifier == identifier)
            .where(RateLimit.endpoint == endpoint)
            .where(RateLimit.attempted_at >= window_start)
        )

        result = await self.db.execute(stmt)
        count = result.scalar() or 0

        logger.debug(
            f"Rate limit check: identifier={identifier}, endpoint={endpoint}, "
            f"window={window_seconds}s, attempts={count}"
        )

        return count

    async def get_recent_attempts(
        self,
        identifier: str,
        endpoint: str,
        window_seconds: int,
    ) -> List[RateLimit]:
        """
        Récupérer toutes les tentatives récentes

        Utile pour debugging ou audit

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            window_seconds: Taille de la fenêtre en secondes

        Returns:
            Liste des tentatives RateLimit
        """
        window_start = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)

        stmt = (
            select(RateLimit)
            .where(RateLimit.identifier == identifier)
            .where(RateLimit.endpoint == endpoint)
            .where(RateLimit.attempted_at >= window_start)
            .order_by(RateLimit.attempted_at.desc())
        )

        result = await self.db.execute(stmt)
        return result.scalars().all()

    # ==========================================
    # NETTOYAGE
    # ==========================================

    async def cleanup_old_attempts(self, older_than_hours: int = 24) -> int:
        """
        Supprimer les tentatives plus anciennes qu'un délai

        À exécuter régulièrement (CRON job quotidien recommandé)

        Args:
            older_than_hours: Supprimer les entrées plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)

        stmt = delete(RateLimit).where(RateLimit.attempted_at < cutoff)

        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        logger.info(f"Cleaned up {count} old rate limit attempts (older than {older_than_hours}h)")

        return count

    async def cleanup_for_endpoint(self, endpoint: str, older_than_hours: int = 24) -> int:
        """
        Supprimer les tentatives d'un endpoint spécifique

        Args:
            endpoint: Endpoint à nettoyer
            older_than_hours: Supprimer les entrées plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)

        stmt = delete(RateLimit).where(
            and_(
                RateLimit.endpoint == endpoint,
                RateLimit.attempted_at < cutoff,
            )
        )

        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        logger.info(
            f"Cleaned up {count} rate limit attempts for endpoint {endpoint} "
            f"(older than {older_than_hours}h)"
        )

        return count

    async def cleanup_for_identifier(
        self, identifier: str, older_than_hours: int = 24
    ) -> int:
        """
        Supprimer les tentatives d'un identifiant spécifique

        Args:
            identifier: Identifiant à nettoyer
            older_than_hours: Supprimer les entrées plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=older_than_hours)

        stmt = delete(RateLimit).where(
            and_(
                RateLimit.identifier == identifier,
                RateLimit.attempted_at < cutoff,
            )
        )

        result = await self.db.execute(stmt)
        await self.db.commit()

        count = result.rowcount
        logger.info(
            f"Cleaned up {count} rate limit attempts for identifier {identifier} "
            f"(older than {older_than_hours}h)"
        )

        return count

    # ==========================================
    # STATISTIQUES ET MONITORING
    # ==========================================

    async def get_endpoint_stats(self, endpoint: str, hours: int = 24) -> Dict:
        """
        Obtenir des statistiques pour un endpoint

        Args:
            endpoint: Endpoint à analyser
            hours: Période d'analyse en heures

        Returns:
            Dictionnaire avec statistiques :
            - total_attempts: Nombre total de tentatives
            - unique_identifiers: Nombre d'identifiants uniques
            - unique_ips: Nombre d'IPs uniques
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        # Total des tentatives
        total_stmt = (
            select(func.count(RateLimit.id))
            .where(RateLimit.endpoint == endpoint)
            .where(RateLimit.attempted_at >= cutoff)
        )
        total_result = await self.db.execute(total_stmt)
        total = total_result.scalar() or 0

        # Identifiants uniques
        unique_identifiers_stmt = (
            select(func.count(func.distinct(RateLimit.identifier)))
            .where(RateLimit.endpoint == endpoint)
            .where(RateLimit.attempted_at >= cutoff)
        )
        unique_identifiers_result = await self.db.execute(unique_identifiers_stmt)
        unique_identifiers = unique_identifiers_result.scalar() or 0

        # IPs uniques
        unique_ips_stmt = (
            select(func.count(func.distinct(RateLimit.ip_address)))
            .where(RateLimit.endpoint == endpoint)
            .where(RateLimit.attempted_at >= cutoff)
            .where(RateLimit.ip_address.isnot(None))
        )
        unique_ips_result = await self.db.execute(unique_ips_stmt)
        unique_ips = unique_ips_result.scalar() or 0

        logger.info(
            f"Endpoint stats for {endpoint}: total={total}, "
            f"unique_identifiers={unique_identifiers}, unique_ips={unique_ips}"
        )

        return {
            "endpoint": endpoint,
            "period_hours": hours,
            "total_attempts": total,
            "unique_identifiers": unique_identifiers,
            "unique_ips": unique_ips,
        }

    async def get_top_offenders(
        self, endpoint: Optional[str] = None, hours: int = 24, limit: int = 10
    ) -> List[Dict]:
        """
        Obtenir les identifiants avec le plus de tentatives

        Utile pour détecter les abus

        Args:
            endpoint: Endpoint à filtrer (optionnel, tous si None)
            hours: Période d'analyse en heures
            limit: Nombre maximum de résultats

        Returns:
            Liste de dictionnaires avec identifier et attempt_count
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        stmt = (
            select(
                RateLimit.identifier,
                func.count(RateLimit.id).label("attempt_count"),
            )
            .where(RateLimit.attempted_at >= cutoff)
            .group_by(RateLimit.identifier)
            .order_by(func.count(RateLimit.id).desc())
            .limit(limit)
        )

        if endpoint:
            stmt = stmt.where(RateLimit.endpoint == endpoint)

        result = await self.db.execute(stmt)
        rows = result.fetchall()

        offenders = [
            {"identifier": row.identifier, "attempt_count": row.attempt_count}
            for row in rows
        ]

        logger.info(
            f"Top {limit} offenders for "
            f"endpoint={endpoint or 'all'} in last {hours}h: {len(offenders)} found"
        )

        return offenders

    async def get_all_endpoints_stats(self, hours: int = 24) -> List[Dict]:
        """
        Obtenir des statistiques pour tous les endpoints

        Args:
            hours: Période d'analyse en heures

        Returns:
            Liste de dictionnaires avec stats par endpoint
        """
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        stmt = (
            select(
                RateLimit.endpoint,
                func.count(RateLimit.id).label("total_attempts"),
                func.count(func.distinct(RateLimit.identifier)).label("unique_identifiers"),
            )
            .where(RateLimit.attempted_at >= cutoff)
            .group_by(RateLimit.endpoint)
            .order_by(func.count(RateLimit.id).desc())
        )

        result = await self.db.execute(stmt)
        rows = result.fetchall()

        stats = [
            {
                "endpoint": row.endpoint,
                "total_attempts": row.total_attempts,
                "unique_identifiers": row.unique_identifiers,
            }
            for row in rows
        ]

        logger.info(f"Retrieved stats for {len(stats)} endpoints in last {hours}h")

        return stats

    # ==========================================
    # VÉRIFICATION RAPIDE
    # ==========================================

    async def is_rate_limited(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        """
        Vérifier si un identifiant a dépassé la limite

        Version optimisée qui ne fait qu'une requête COUNT

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            limit: Nombre maximum de tentatives autorisées
            window_seconds: Fenêtre de temps en secondes

        Returns:
            True si la limite est dépassée, False sinon
        """
        attempts = await self.count_attempts(identifier, endpoint, window_seconds)
        return attempts >= limit

    async def check_and_record(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[bool, int]:
        """
        Vérifier la limite ET enregistrer la tentative en une opération

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            limit: Nombre maximum de tentatives autorisées
            window_seconds: Fenêtre de temps en secondes
            ip_address: Adresse IP du client
            user_agent: User agent du client

        Returns:
            Tuple (is_allowed, current_attempts):
            - is_allowed: True si la requête est autorisée
            - current_attempts: Nombre de tentatives actuelles (après enregistrement)
        """
        # 1. Compter les tentatives existantes
        current_attempts = await self.count_attempts(identifier, endpoint, window_seconds)

        # 2. Vérifier si la limite est dépassée
        is_allowed = current_attempts < limit

        # 3. Enregistrer la tentative (même si rejetée, pour l'audit)
        await self.record_attempt(identifier, endpoint, ip_address, user_agent)

        # 4. Incrémenter le compteur après enregistrement
        current_attempts += 1

        if not is_allowed:
            logger.warning(
                f"Rate limit exceeded: identifier={identifier}, endpoint={endpoint}, "
                f"attempts={current_attempts}, limit={limit}"
            )

        return is_allowed, current_attempts
