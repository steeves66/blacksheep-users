"""
RateLimitService - Logique métier pour le rate limiting

Service de haut niveau qui orchestre :
- Vérification des limites de taux
- Enregistrement des tentatives
- Nettoyage automatique
- Statistiques et monitoring
- Gestion des whitelist/blacklist (futures fonctionnalités)

Utilise le RateLimitRepository pour toutes les opérations DB
"""

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from repositories.rate_limit_repository import RateLimitRepository

logger = logging.getLogger(__name__)


class RateLimitService:
    """Service pour gérer le rate limiting"""

    def __init__(self, rate_limit_repo: RateLimitRepository):
        """
        Initialise le service avec le repository

        Args:
            rate_limit_repo: Repository pour les opérations de rate limiting
        """
        self.repo = rate_limit_repo

    # ==========================================
    # VÉRIFICATION DES LIMITES
    # ==========================================

    async def check_rate_limit(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[bool, int, Optional[int]]:
        """
        Vérifier si une requête est autorisée selon le rate limiting

        Cette méthode :
        1. Vérifie le nombre de tentatives dans la fenêtre
        2. Enregistre la tentative actuelle
        3. Retourne si la requête est autorisée

        Args:
            identifier: Identifiant unique (ip:xxx ou user:xxx)
            endpoint: Endpoint concerné
            limit: Nombre maximum de tentatives autorisées
            window_seconds: Fenêtre de temps en secondes
            ip_address: Adresse IP du client (pour audit)
            user_agent: User agent du client (pour audit)

        Returns:
            Tuple (is_allowed, current_attempts, retry_after):
            - is_allowed: True si la requête est autorisée
            - current_attempts: Nombre de tentatives actuelles
            - retry_after: Secondes à attendre avant de réessayer (None si autorisé)
        """
        is_allowed, current_attempts = await self.repo.check_and_record(
            identifier=identifier,
            endpoint=endpoint,
            limit=limit,
            window_seconds=window_seconds,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Calculer le temps d'attente si refusé
        retry_after = window_seconds if not is_allowed else None

        if not is_allowed:
            logger.warning(
                f"Rate limit blocked: identifier={identifier}, endpoint={endpoint}, "
                f"attempts={current_attempts}/{limit}, retry_after={retry_after}s"
            )
        else:
            logger.debug(
                f"Rate limit allowed: identifier={identifier}, endpoint={endpoint}, "
                f"attempts={current_attempts}/{limit}"
            )

        return is_allowed, current_attempts, retry_after

    async def is_rate_limited(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        """
        Vérifier si un identifiant est rate limited (SANS enregistrer)

        Utile pour des vérifications préalables

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            limit: Nombre maximum de tentatives
            window_seconds: Fenêtre de temps en secondes

        Returns:
            True si rate limited (limite dépassée)
        """
        return await self.repo.is_rate_limited(identifier, endpoint, limit, window_seconds)

    # ==========================================
    # GESTION DES TENTATIVES
    # ==========================================

    async def get_remaining_attempts(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> int:
        """
        Obtenir le nombre de tentatives restantes

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            limit: Nombre maximum de tentatives
            window_seconds: Fenêtre de temps en secondes

        Returns:
            Nombre de tentatives restantes (0 si limite dépassée)
        """
        current = await self.repo.count_attempts(identifier, endpoint, window_seconds)
        remaining = max(0, limit - current)

        logger.debug(
            f"Remaining attempts: identifier={identifier}, endpoint={endpoint}, "
            f"remaining={remaining}/{limit}"
        )

        return remaining

    async def get_current_attempts(
        self,
        identifier: str,
        endpoint: str,
        window_seconds: int,
    ) -> int:
        """
        Obtenir le nombre de tentatives actuelles

        Args:
            identifier: Identifiant unique
            endpoint: Endpoint concerné
            window_seconds: Fenêtre de temps en secondes

        Returns:
            Nombre de tentatives dans la fenêtre
        """
        return await self.repo.count_attempts(identifier, endpoint, window_seconds)

    # ==========================================
    # NETTOYAGE
    # ==========================================

    async def cleanup_old_data(self, older_than_hours: int = 24) -> int:
        """
        Nettoyer les anciennes tentatives

        Recommandé : Exécuter quotidiennement via CRON job

        Args:
            older_than_hours: Supprimer les données plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        count = await self.repo.cleanup_old_attempts(older_than_hours)

        logger.info(
            f"Rate limit cleanup completed: {count} entries deleted "
            f"(older than {older_than_hours}h)"
        )

        return count

    async def cleanup_endpoint(self, endpoint: str, older_than_hours: int = 24) -> int:
        """
        Nettoyer les tentatives d'un endpoint spécifique

        Args:
            endpoint: Endpoint à nettoyer
            older_than_hours: Supprimer les données plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        count = await self.repo.cleanup_for_endpoint(endpoint, older_than_hours)

        logger.info(
            f"Endpoint cleanup completed: {count} entries deleted for {endpoint} "
            f"(older than {older_than_hours}h)"
        )

        return count

    async def cleanup_identifier(self, identifier: str, older_than_hours: int = 24) -> int:
        """
        Nettoyer les tentatives d'un identifiant spécifique

        Utile pour réinitialiser un utilisateur/IP après résolution d'incident

        Args:
            identifier: Identifiant à nettoyer
            older_than_hours: Supprimer les données plus vieilles que X heures

        Returns:
            Nombre d'entrées supprimées
        """
        count = await self.repo.cleanup_for_identifier(identifier, older_than_hours)

        logger.info(
            f"Identifier cleanup completed: {count} entries deleted for {identifier} "
            f"(older than {older_than_hours}h)"
        )

        return count

    # ==========================================
    # STATISTIQUES ET MONITORING
    # ==========================================

    async def get_endpoint_statistics(self, endpoint: str, hours: int = 24) -> Dict:
        """
        Obtenir des statistiques détaillées pour un endpoint

        Args:
            endpoint: Endpoint à analyser
            hours: Période d'analyse en heures

        Returns:
            Dictionnaire avec statistiques complètes
        """
        stats = await self.repo.get_endpoint_stats(endpoint, hours)

        logger.info(
            f"Endpoint statistics retrieved: {endpoint}, "
            f"total={stats['total_attempts']}, period={hours}h"
        )

        return stats

    async def get_all_endpoints_statistics(self, hours: int = 24) -> List[Dict]:
        """
        Obtenir des statistiques pour tous les endpoints

        Args:
            hours: Période d'analyse en heures

        Returns:
            Liste de statistiques par endpoint
        """
        stats = await self.repo.get_all_endpoints_stats(hours)

        logger.info(f"All endpoints statistics retrieved: {len(stats)} endpoints, period={hours}h")

        return stats

    async def get_top_offenders(
        self,
        endpoint: Optional[str] = None,
        hours: int = 24,
        limit: int = 10,
    ) -> List[Dict]:
        """
        Obtenir les identifiants avec le plus de tentatives

        Utile pour détecter les abus et attaques

        Args:
            endpoint: Endpoint à filtrer (optionnel)
            hours: Période d'analyse en heures
            limit: Nombre maximum de résultats

        Returns:
            Liste d'identifiants avec leur nombre de tentatives
        """
        offenders = await self.repo.get_top_offenders(endpoint, hours, limit)

        logger.info(
            f"Top offenders retrieved: {len(offenders)} found, "
            f"endpoint={endpoint or 'all'}, period={hours}h"
        )

        return offenders

    async def generate_monitoring_report(self, hours: int = 24) -> Dict:
        """
        Générer un rapport complet de monitoring

        Utile pour dashboards et alertes

        Args:
            hours: Période d'analyse en heures

        Returns:
            Dictionnaire avec rapport complet :
            - timestamp: Date du rapport
            - period_hours: Période analysée
            - endpoints: Statistiques par endpoint
            - top_offenders: Principaux identifiants suspects
            - summary: Résumé global
        """
        # Récupérer toutes les stats
        endpoints_stats = await self.get_all_endpoints_statistics(hours)
        top_offenders = await self.get_top_offenders(hours=hours, limit=20)

        # Calculer le résumé global
        total_attempts = sum(stat["total_attempts"] for stat in endpoints_stats)
        total_unique_identifiers = sum(
            stat["unique_identifiers"] for stat in endpoints_stats
        )
        total_endpoints = len(endpoints_stats)

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "period_hours": hours,
            "summary": {
                "total_attempts": total_attempts,
                "total_unique_identifiers": total_unique_identifiers,
                "total_endpoints": total_endpoints,
            },
            "endpoints": endpoints_stats,
            "top_offenders": top_offenders,
        }

        logger.info(
            f"Monitoring report generated: period={hours}h, "
            f"total_attempts={total_attempts}, endpoints={total_endpoints}"
        )

        return report

    # ==========================================
    # UTILITAIRES
    # ==========================================

    async def reset_identifier(self, identifier: str) -> int:
        """
        Réinitialiser complètement un identifiant (supprimer toutes ses tentatives)

        Utile pour débloquer un utilisateur/IP manuellement

        Args:
            identifier: Identifiant à réinitialiser

        Returns:
            Nombre d'entrées supprimées
        """
        count = await self.repo.cleanup_for_identifier(identifier, older_than_hours=0)

        logger.warning(
            f"Identifier reset: {identifier}, {count} attempts deleted (manual reset)"
        )

        return count

    async def get_identifier_status(
        self,
        identifier: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> Dict:
        """
        Obtenir le statut complet d'un identifiant pour un endpoint

        Args:
            identifier: Identifiant à vérifier
            endpoint: Endpoint concerné
            limit: Limite de tentatives
            window_seconds: Fenêtre de temps en secondes

        Returns:
            Dictionnaire avec :
            - identifier: L'identifiant
            - endpoint: L'endpoint
            - current_attempts: Nombre de tentatives actuelles
            - limit: Limite configurée
            - remaining: Tentatives restantes
            - is_rate_limited: Si actuellement rate limited
        """
        current_attempts = await self.get_current_attempts(
            identifier, endpoint, window_seconds
        )
        remaining = max(0, limit - current_attempts)
        is_limited = current_attempts >= limit

        status = {
            "identifier": identifier,
            "endpoint": endpoint,
            "current_attempts": current_attempts,
            "limit": limit,
            "remaining": remaining,
            "is_rate_limited": is_limited,
            "window_seconds": window_seconds,
        }

        logger.debug(
            f"Identifier status: {identifier}, endpoint={endpoint}, "
            f"attempts={current_attempts}/{limit}, rate_limited={is_limited}"
        )

        return status
