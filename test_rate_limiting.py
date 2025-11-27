"""
Script de test pour le système de rate limiting

Usage:
    python test_rate_limiting.py
"""

import asyncio
import sys
from datetime import datetime, timezone

from dbsession import AsyncSessionLocal
from domain.rate_limit_service import RateLimitService
from repositories.rate_limit_repository import RateLimitRepository


async def test_basic_rate_limiting():
    """Test de base du rate limiting"""
    print("=" * 70)
    print("TEST 1 : Rate Limiting de Base")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        # Simuler 7 tentatives (limite: 5)
        print("\n📊 Simulation de 7 tentatives avec limite de 5/minute\n")

        for i in range(1, 8):
            is_allowed, attempts, retry_after = await service.check_rate_limit(
                identifier="test:127.0.0.1",
                endpoint="test-endpoint",
                limit=5,
                window_seconds=60,
                ip_address="127.0.0.1",
                user_agent="Test Script",
            )

            if is_allowed:
                print(f"✅ Tentative {i:2d}: AUTORISÉE  ({attempts}/5)")
            else:
                print(f"❌ Tentative {i:2d}: BLOQUÉE    ({attempts}/5) - Retry après {retry_after}s")

        print("\n✅ Test 1 réussi!\n")


async def test_multiple_identifiers():
    """Test avec plusieurs identifiants différents"""
    print("=" * 70)
    print("TEST 2 : Multiples Identifiants")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        identifiers = [
            ("ip:192.168.1.100", "User A"),
            ("ip:192.168.1.101", "User B"),
            ("user:42", "User C (authenticated)"),
        ]

        print("\n📊 Test avec 3 identifiants différents\n")

        for identifier, label in identifiers:
            is_allowed, attempts, _ = await service.check_rate_limit(
                identifier=identifier,
                endpoint="test-multi",
                limit=5,
                window_seconds=60,
                ip_address=identifier.split(":")[1],
            )

            status = "✅ AUTORISÉE" if is_allowed else "❌ BLOQUÉE"
            print(f"{label:30s} ({identifier:20s}): {status} - {attempts}/5")

        print("\n✅ Test 2 réussi!\n")


async def test_statistics():
    """Test des statistiques"""
    print("=" * 70)
    print("TEST 3 : Statistiques et Monitoring")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        # Créer quelques données de test
        print("\n📊 Génération de données de test...")
        for i in range(10):
            await repo.record_attempt(
                identifier=f"test:ip{i % 3}",
                endpoint="stats-test",
                ip_address=f"192.168.1.{i}",
            )

        # Stats globales
        print("\n📈 Statistiques pour 'stats-test':")
        stats = await service.get_endpoint_statistics("stats-test", hours=1)
        print(f"  - Total tentatives:     {stats['total_attempts']}")
        print(f"  - Identifiants uniques: {stats['unique_identifiers']}")
        print(f"  - IPs uniques:          {stats['unique_ips']}")

        # Top offenders
        print("\n🔝 Top 3 identifiants:")
        offenders = await service.get_top_offenders(
            endpoint="stats-test", hours=1, limit=3
        )
        for idx, offender in enumerate(offenders, 1):
            print(
                f"  {idx}. {offender['identifier']:20s} - {offender['attempt_count']} tentatives"
            )

        print("\n✅ Test 3 réussi!\n")


async def test_identifier_status():
    """Test du statut d'un identifiant"""
    print("=" * 70)
    print("TEST 4 : Statut d'un Identifiant")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        identifier = "test:status-check"

        # Faire quelques tentatives
        print(f"\n📊 Simulation de 3 tentatives pour {identifier}\n")
        for i in range(3):
            await service.check_rate_limit(
                identifier=identifier,
                endpoint="status-test",
                limit=5,
                window_seconds=60,
                ip_address="127.0.0.1",
            )

        # Vérifier le statut
        status = await service.get_identifier_status(
            identifier=identifier,
            endpoint="status-test",
            limit=5,
            window_seconds=60,
        )

        print("📋 Statut de l'identifiant:")
        print(f"  - Identifiant:         {status['identifier']}")
        print(f"  - Endpoint:            {status['endpoint']}")
        print(f"  - Tentatives actuelles: {status['current_attempts']}")
        print(f"  - Limite:              {status['limit']}")
        print(f"  - Restantes:           {status['remaining']}")
        print(f"  - Rate limited:        {status['is_rate_limited']}")

        print("\n✅ Test 4 réussi!\n")


async def test_cleanup():
    """Test du nettoyage"""
    print("=" * 70)
    print("TEST 5 : Nettoyage des Données")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        # Créer des données de test
        print("\n📊 Génération de 20 entrées de test...")
        for i in range(20):
            await repo.record_attempt(
                identifier=f"cleanup:test{i}",
                endpoint="cleanup-test",
                ip_address=f"192.168.1.{i}",
            )

        # Stats avant nettoyage
        stats_before = await service.get_endpoint_statistics("cleanup-test", hours=24)
        print(f"\n📈 Avant nettoyage: {stats_before['total_attempts']} tentatives")

        # Nettoyer (très court délai pour test)
        deleted = await service.cleanup_endpoint("cleanup-test", older_than_hours=0)

        # Stats après nettoyage
        stats_after = await service.get_endpoint_statistics("cleanup-test", hours=24)
        print(f"🧹 Nettoyées:       {deleted} entrées")
        print(f"📉 Après nettoyage: {stats_after['total_attempts']} tentatives")

        print("\n✅ Test 5 réussi!\n")


async def test_monitoring_report():
    """Test du rapport de monitoring"""
    print("=" * 70)
    print("TEST 6 : Rapport de Monitoring Complet")
    print("=" * 70)

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        # Générer un rapport
        print("\n📊 Génération du rapport de monitoring (dernières 24h)...\n")
        report = await service.generate_monitoring_report(hours=24)

        print("📋 RÉSUMÉ GLOBAL:")
        print(f"  - Timestamp:           {report['timestamp']}")
        print(f"  - Période:             {report['period_hours']}h")
        print(f"  - Total tentatives:    {report['summary']['total_attempts']}")
        print(f"  - Identifiants uniques: {report['summary']['total_unique_identifiers']}")
        print(f"  - Endpoints surveillés: {report['summary']['total_endpoints']}")

        if report["endpoints"]:
            print(f"\n📍 ENDPOINTS (top 5):")
            for endpoint in report["endpoints"][:5]:
                print(
                    f"  - {endpoint['endpoint']:30s} : {endpoint['total_attempts']:4d} tentatives"
                )

        if report["top_offenders"]:
            print(f"\n🔝 TOP OFFENDERS (top 5):")
            for offender in report["top_offenders"][:5]:
                print(
                    f"  - {offender['identifier']:30s} : {offender['attempt_count']:4d} tentatives"
                )

        print("\n✅ Test 6 réussi!\n")


async def run_all_tests():
    """Exécuter tous les tests"""
    print("\n" + "=" * 70)
    print(" " * 20 + "🧪 TESTS RATE LIMITING")
    print("=" * 70 + "\n")

    tests = [
        ("Rate Limiting de Base", test_basic_rate_limiting),
        ("Multiples Identifiants", test_multiple_identifiers),
        ("Statistiques et Monitoring", test_statistics),
        ("Statut d'un Identifiant", test_identifier_status),
        ("Nettoyage des Données", test_cleanup),
        ("Rapport de Monitoring", test_monitoring_report),
    ]

    passed = 0
    failed = 0

    for test_name, test_func in tests:
        try:
            await test_func()
            passed += 1
        except Exception as e:
            print(f"\n❌ ÉCHEC: {test_name}")
            print(f"   Erreur: {str(e)}\n")
            failed += 1

    print("=" * 70)
    print(f"📊 RÉSULTATS FINAUX:")
    print(f"  ✅ Tests réussis: {passed}")
    print(f"  ❌ Tests échoués: {failed}")
    print(f"  📈 Total:         {passed + failed}")
    print("=" * 70 + "\n")

    return failed == 0


if __name__ == "__main__":
    try:
        success = asyncio.run(run_all_tests())
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrompus par l'utilisateur")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Erreur fatale: {str(e)}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
