# 🛡️ Rate Limiting - Documentation Complète

## 📋 Vue d'ensemble

Le système de rate limiting a été implémenté pour protéger l'application contre les abus et les attaques par force brute. Il suit une architecture en couches avec Repository Pattern et Service Layer.

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│         Routes / Controllers            │
│         (user_controller.py)            │
└──────────────┬──────────────────────────┘
               │ utilise
               ▼
┌─────────────────────────────────────────┐
│         Décorateur @rate_limit          │
│         (helpers/decorators.py)         │
└──────────────┬──────────────────────────┘
               │ utilise
               ▼
┌─────────────────────────────────────────┐
│         RateLimitService                │
│     (domain/rate_limit_service.py)      │
│  - Logique métier                       │
│  - Vérification des limites             │
│  - Statistiques                         │
└──────────────┬──────────────────────────┘
               │ utilise
               ▼
┌─────────────────────────────────────────┐
│      RateLimitRepository                │
│  (repositories/rate_limit_repository.py)│
│  - Accès à la base de données           │
│  - Requêtes SQL                         │
└──────────────┬──────────────────────────┘
               │ utilise
               ▼
┌─────────────────────────────────────────┐
│         Modèle RateLimit                │
│         (model/user.py)                 │
│  - Structure de données                 │
│  - Table SQLAlchemy                     │
└─────────────────────────────────────────┘
```

## 📂 Fichiers créés/modifiés

### ✅ Nouveaux fichiers

1. **`repositories/rate_limit_repository.py`** (429 lignes)
   - Repository pour les opérations de base de données
   - Méthodes CRUD pour les tentatives
   - Statistiques et monitoring
   - Nettoyage des anciennes données

2. **`domain/rate_limit_service.py`** (403 lignes)
   - Service de haut niveau
   - Logique métier du rate limiting
   - Génération de rapports
   - Utilitaires de gestion

### ✏️ Fichiers modifiés

1. **`helpers/decorators.py`**
   - Refactorisation de `_check_rate_limit()` (lignes 214-291)
   - Utilise maintenant `RateLimitService` au lieu de requêtes SQL directes
   - Code plus propre et maintenable

2. **`app/controllers/user_controller.py`**
   - Ajout de `@rate_limit` sur `/users/resend-verification` (ligne 177)

### 📊 Fichiers existants (déjà en place)

1. **`model/user.py`**
   - Modèle `RateLimit` (lignes 388-424)
   - Table avec identifier, endpoint, attempted_at, etc.

## 🔒 Routes protégées

| Route | Limite | Fenêtre | Scope | Description |
|-------|--------|---------|-------|-------------|
| `POST /users/register` | 5 req | 1 heure | `register` | Inscription utilisateur |
| `POST /users/resend-verification` | 5 req | 1 heure | `resend` | Renvoi email vérification |
| `POST /users/login` | 5 req | 5 minutes | `login` | Connexion utilisateur |
| `POST /users/forgot-password` | 3 req | 15 minutes | `forgot-password` | Demande reset mot de passe |
| `GET /session/test` | 10 req | 1 minute | `session-test` | Test de session (dev) |

## 🔧 Utilisation du décorateur

### Syntaxe de base

```python
from helpers.decorators import rate_limit

@post("/endpoint")
@rate_limit(limit=5, per_seconds=3600, by="ip_or_user", scope="my-scope")
async def my_endpoint(self, request: Request) -> Response:
    # Votre code ici
    pass
```

### Paramètres

- **`limit`** (int, requis) : Nombre maximum de tentatives autorisées
- **`per_seconds`** (int, requis) : Fenêtre de temps en secondes
- **`by`** (str, optionnel) : Stratégie d'identification
  - `"ip"` : Par adresse IP uniquement
  - `"user"` : Par utilisateur connecté (sinon IP)
  - `"ip_or_user"` : Par utilisateur si connecté, sinon IP (défaut)
- **`scope`** (str, optionnel) : Grouper plusieurs endpoints sous la même règle

### Exemples

```python
# Limite par IP (même pour utilisateurs connectés)
@rate_limit(limit=10, per_seconds=60, by="ip")

# Limite stricte par utilisateur
@rate_limit(limit=5, per_seconds=300, by="user")

# Grouper plusieurs endpoints
@rate_limit(limit=3, per_seconds=900, scope="password-management")
```

## 📊 Modèle de données

### Table `rate_limits`

```sql
CREATE TABLE rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier VARCHAR(255) NOT NULL,      -- Format: "ip:xxx.xxx.xxx.xxx" ou "user:123"
    endpoint VARCHAR(255) NOT NULL,        -- Endpoint ou scope
    attempted_at DATETIME NOT NULL,        -- Timestamp UTC
    ip_address VARCHAR(45),                -- Adresse IP du client
    user_agent VARCHAR(500),               -- User agent du navigateur

    INDEX idx_identifier_endpoint_time (identifier, endpoint, attempted_at),
    INDEX idx_endpoint_time (endpoint, attempted_at)
);
```

### Exemple de données

| id | identifier | endpoint | attempted_at | ip_address |
|----|------------|----------|--------------|------------|
| 1 | ip:192.168.1.100 | register | 2025-11-27 10:30:00 | 192.168.1.100 |
| 2 | user:42 | login | 2025-11-27 10:31:00 | 192.168.1.100 |
| 3 | ip:192.168.1.100 | forgot-password | 2025-11-27 10:32:00 | 192.168.1.100 |

## 🔍 RateLimitRepository - API

### Enregistrement

```python
repo = RateLimitRepository(db)

# Enregistrer une tentative
await repo.record_attempt(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0..."
)
```

### Comptage

```python
# Compter les tentatives dans une fenêtre
count = await repo.count_attempts(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    window_seconds=3600
)

# Vérifier si rate limited
is_limited = await repo.is_rate_limited(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    limit=5,
    window_seconds=3600
)
```

### Nettoyage

```python
# Nettoyer les anciennes tentatives
deleted_count = await repo.cleanup_old_attempts(older_than_hours=24)

# Nettoyer par endpoint
deleted_count = await repo.cleanup_for_endpoint(
    endpoint="/users/register",
    older_than_hours=24
)

# Nettoyer par identifiant
deleted_count = await repo.cleanup_for_identifier(
    identifier="ip:192.168.1.100",
    older_than_hours=24
)
```

### Statistiques

```python
# Stats pour un endpoint
stats = await repo.get_endpoint_stats(endpoint="/users/register", hours=24)
# {
#     "endpoint": "/users/register",
#     "period_hours": 24,
#     "total_attempts": 150,
#     "unique_identifiers": 45,
#     "unique_ips": 42
# }

# Top offenders (abus)
offenders = await repo.get_top_offenders(
    endpoint="/users/register",
    hours=24,
    limit=10
)
# [
#     {"identifier": "ip:192.168.1.100", "attempt_count": 25},
#     {"identifier": "user:42", "attempt_count": 18},
#     ...
# ]
```

## 🎯 RateLimitService - API

### Vérification

```python
service = RateLimitService(repo)

# Vérifier et enregistrer en une opération
is_allowed, current_attempts, retry_after = await service.check_rate_limit(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    limit=5,
    window_seconds=3600,
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0..."
)

if not is_allowed:
    print(f"Rate limited! {current_attempts}/5 attempts. Retry after {retry_after}s")
```

### Informations

```python
# Tentatives restantes
remaining = await service.get_remaining_attempts(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    limit=5,
    window_seconds=3600
)

# Statut complet
status = await service.get_identifier_status(
    identifier="ip:192.168.1.100",
    endpoint="/users/register",
    limit=5,
    window_seconds=3600
)
# {
#     "identifier": "ip:192.168.1.100",
#     "endpoint": "/users/register",
#     "current_attempts": 3,
#     "limit": 5,
#     "remaining": 2,
#     "is_rate_limited": False,
#     "window_seconds": 3600
# }
```

### Monitoring

```python
# Rapport complet
report = await service.generate_monitoring_report(hours=24)
# {
#     "timestamp": "2025-11-27T10:30:00Z",
#     "period_hours": 24,
#     "summary": {
#         "total_attempts": 1500,
#         "total_unique_identifiers": 250,
#         "total_endpoints": 5
#     },
#     "endpoints": [...],
#     "top_offenders": [...]
# }
```

### Utilitaires

```python
# Réinitialiser un identifiant (débloquer)
deleted = await service.reset_identifier("ip:192.168.1.100")

# Nettoyage programmé (CRON quotidien recommandé)
deleted = await service.cleanup_old_data(older_than_hours=24)
```

## 📈 Réponses HTTP

### ✅ Requête autorisée

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "success": true,
  "message": "Utilisateur créé avec succès"
}
```

### ❌ Rate limit dépassé (API)

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 3600
Content-Type: application/json

{
  "error": "too_many_requests",
  "message": "Trop de tentatives, veuillez réessayer plus tard.",
  "limit": 5,
  "per_seconds": 3600,
  "current_attempts": 6,
  "retry_after": 3600
}
```

### ❌ Rate limit dépassé (HTML)

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 3600
Location: /error/rate-limit?message=Trop+de+tentatives&retry_after=3600
```

## 🧪 Tests

### Test manuel avec curl

```bash
# Tester le rate limit sur /users/register
for i in {1..6}; do
  echo "Tentative $i:"
  curl -X POST http://localhost:8000/users/register \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "username=test$i&email=test$i@example.com&password=Password123&confirm_password=Password123"
  echo -e "\n---"
  sleep 1
done
```

### Vérifier les stats (admin)

```bash
curl http://localhost:8000/users/admin/rate-limits | jq
```

### Script Python de test

```python
import asyncio
from dbsession import AsyncSessionLocal
from repositories.rate_limit_repository import RateLimitRepository
from domain.rate_limit_service import RateLimitService

async def test_rate_limiting():
    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        # Simuler 6 tentatives (limite: 5)
        for i in range(1, 7):
            is_allowed, attempts, retry_after = await service.check_rate_limit(
                identifier="ip:127.0.0.1",
                endpoint="test-endpoint",
                limit=5,
                window_seconds=60,
                ip_address="127.0.0.1"
            )

            print(f"Tentative {i}: allowed={is_allowed}, attempts={attempts}")

            if not is_allowed:
                print(f"❌ Rate limited! Retry after {retry_after}s")
                break

asyncio.run(test_rate_limiting())
```

## 🔧 Maintenance

### Nettoyage automatique (CRON)

Ajouter à votre crontab :

```bash
# Nettoyer les tentatives de plus de 24h tous les jours à 3h du matin
0 3 * * * cd /path/to/project && python -c "
import asyncio
from dbsession import AsyncSessionLocal
from repositories.rate_limit_repository import RateLimitRepository
from domain.rate_limit_service import RateLimitService

async def cleanup():
    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)
        deleted = await service.cleanup_old_data(older_than_hours=24)
        print(f'Cleaned up {deleted} rate limit entries')

asyncio.run(cleanup())
"
```

### Monitoring

Créer un endpoint admin pour les statistiques :

```python
@get("/admin/rate-limit-stats")
@require_role("admin")
async def rate_limit_stats(self, request: Request) -> Response:
    from dbsession import AsyncSessionLocal
    from repositories.rate_limit_repository import RateLimitRepository
    from domain.rate_limit_service import RateLimitService

    async with AsyncSessionLocal() as db:
        repo = RateLimitRepository(db)
        service = RateLimitService(repo)

        report = await service.generate_monitoring_report(hours=24)

        return json(report)
```

## 🚀 Bonnes pratiques

### ✅ Recommandations

1. **Limites progressives** :
   - Actions sensibles (login, reset password) : 3-5 tentatives / 15min
   - Actions normales (register, resend) : 5-10 tentatives / heure
   - Actions de lecture : 50-100 tentatives / minute

2. **Stratégie d'identification** :
   - `by="ip"` pour les endpoints publics (avant authentification)
   - `by="user"` pour les endpoints authentifiés
   - `by="ip_or_user"` pour les endpoints mixtes

3. **Groupement par scope** :
   - Grouper les endpoints liés sous le même scope
   - Exemple : `scope="password-management"` pour `/forgot-password` et `/reset-password`

4. **Messages d'erreur** :
   - Toujours inclure `Retry-After` header
   - Messages clairs pour l'utilisateur
   - Logger les abus pour investigation

### ⚠️ À éviter

1. ❌ Limites trop strictes (frustration utilisateur)
2. ❌ Limites trop permissives (inefficace contre attaques)
3. ❌ Oublier le nettoyage des anciennes données (croissance DB)
4. ❌ Exposer des infos sensibles dans les messages d'erreur

## 📚 Références

- **RFC 6585** : HTTP Status Code 429 (Too Many Requests)
- **OWASP** : Rate Limiting Best Practices
- **BlackSheep** : https://www.neoteroi.dev/blacksheep/

## 🎉 Résumé

Le système de rate limiting est maintenant complètement opérationnel avec :

✅ Architecture en couches propre (Repository + Service + Decorator)
✅ 5 routes protégées contre les abus
✅ Statistiques et monitoring intégrés
✅ API flexible et réutilisable
✅ Nettoyage automatique des données
✅ Support JSON et HTML
✅ Logging complet pour audit

**Prêt pour la production !** 🚀
