# Architecture Modulaire d'Authentification - Version Complète

Documentation complète de l'architecture modulaire pour les fonctionnalités d'authentification avec Controllers, Services, et Repositories.

## 🎯 Objectif

Découper le code d'authentification en modules indépendants selon une architecture en couches :
- **Controllers** : Gestion des requêtes HTTP et des vues
- **Services** : Logique métier
- **Repositories** : Accès aux données

## 📁 Structure Complète

```
app/
├── controllers/
│   └── auth/
│       ├── __init__.py                           # Expose tous les contrôleurs
│       ├── register_controller.py                # Inscription simple
│       ├── register_verified_controller.py       # Inscription avec email
│       ├── auth_controller.py                    # Login + Logout
│       └── reset_password_controller.py          # Réinitialisation
│
├── views/
│   └── auth/
│       ├── register/                             # Templates inscription simple
│       ├── register_verified/                    # Templates inscription avec email
│       ├── login/                                # Templates connexion
│       ├── logout/                               # Templates déconnexion
│       └── reset_password/                       # Templates réinitialisation
│
domain/
└── auth/
    ├── __init__.py                               # Expose tous les services
    ├── register_service.py                       # Service inscription simple
    ├── register_verified_service.py              # Service inscription avec email
    ├── auth_service.py                           # Service login + logout
    └── reset_password_service.py                 # Service réinitialisation
│
repositories/
└── auth/
    ├── __init__.py                               # Expose tous les repositories
    ├── register_repository.py                    # Repository inscription simple
    ├── register_verified_repository.py           # Repository inscription avec email
    ├── auth_repository.py                        # Repository login + logout
    └── reset_password_repository.py              # Repository réinitialisation
```

## 🔧 Fonctionnalités

### 1. **Register Simple** (Inscription sans vérification email)

**Contrôleur:** `RegisterController`
**Service:** `RegisterService`
**Repository:** `RegisterRepository`

**Routes:**
- `GET  /auth/register` - Formulaire d'inscription
- `POST /auth/register` - Traiter l'inscription
- `GET  /auth/register/success` - Page de succès

**Responsabilités par couche:**

| Couche | Responsabilités |
|--------|-----------------|
| **Controller** | - Affichage formulaire<br>- Validation entrées<br>- Redirection |
| **Service** | - Hash du mot de passe<br>- Orchestration<br>- Validation métier |
| **Repository** | - Vérification existence email<br>- Création utilisateur en DB |

---

### 2. **Register Verified** (Inscription avec vérification email)

**Contrôleur:** `RegisterVerifiedController`
**Service:** `RegisterVerifiedService`
**Repository:** `RegisterVerifiedRepository`

**Routes:**
- `GET  /auth/register-verified` - Formulaire d'inscription
- `POST /auth/register-verified` - Traiter l'inscription
- `GET  /auth/register-verified/verify-email/{token}` - Vérifier l'email
- `GET  /auth/register-verified/resend-verification` - Formulaire de renvoi
- `POST /auth/register-verified/resend-verification` - Renvoyer l'email
- `GET  /auth/register-verified/account-active` - Compte déjà actif

**Responsabilités par couche:**

| Couche | Responsabilités |
|--------|-----------------|
| **Controller** | - Affichage formulaires<br>- Gestion des redirections<br>- Gestion des erreurs (token expiré, etc.) |
| **Service** | - Hash du mot de passe<br>- Génération/signature tokens<br>- Envoi emails (confirmation, remerciement, bienvenue)<br>- Vérification tokens |
| **Repository** | - Création utilisateur inactif<br>- CRUD tokens de vérification<br>- Activation utilisateur |

**Emails envoyés:**
1. **Confirmation de création** : Lors de l'inscription
2. **Vérification** : Email avec lien de vérification
3. **Remerciement** : Après activation du compte
4. **Bienvenue** : Message de bienvenue après activation

---

### 3. **Auth** (Login + Logout)

**Contrôleur:** `AuthController`
**Service:** `AuthService`
**Repository:** `AuthRepository`

**Routes:**
- `GET  /auth/login` - Formulaire de connexion
- `POST /auth/login` - Traiter la connexion
- `GET  /auth/login/success` - Page de succès connexion
- `GET  /auth/logout` - Déconnecter l'utilisateur
- `GET  /auth/logout/success` - Page de succès déconnexion

**Responsabilités par couche:**

| Couche | Responsabilités |
|--------|-----------------|
| **Controller** | - Affichage formulaire login<br>- Gestion de la session<br>- Suppression session (logout) |
| **Service** | - Authentification<br>- Vérification mot de passe<br>- Vérification compte actif<br>- Logs déconnexion |
| **Repository** | - Récupération utilisateur par email<br>- Récupération utilisateur par username |

**Caractéristiques:**
- Rate limiting : 5 tentatives par 5 minutes
- Support email ET username pour login
- Vérification compte actif
- Gestion session sécurisée

---

### 4. **Reset Password** (Réinitialisation du mot de passe)

**Contrôleur:** `ResetPasswordController`
**Service:** `ResetPasswordService`
**Repository:** `ResetPasswordRepository`

**Routes:**
- `GET  /auth/reset-password/forgot-password` - Formulaire demande reset
- `POST /auth/reset-password/forgot-password` - Traiter demande reset
- `GET  /auth/reset-password/reset/{token}` - Formulaire nouveau mot de passe
- `POST /auth/reset-password/reset/{token}` - Traiter nouveau mot de passe
- `GET  /auth/reset-password/success` - Page de succès

**Responsabilités par couche:**

| Couche | Responsabilités |
|--------|-----------------|
| **Controller** | - Affichage formulaires<br>- Validation mot de passe<br>- Gestion erreurs (token expiré) |
| **Service** | - Génération/signature tokens<br>- Vérification tokens<br>- Hash nouveau mot de passe<br>- Protection contre énumération |
| **Repository** | - CRUD tokens de réinitialisation<br>- Mise à jour mot de passe |

**Sécurité:**
- Token avec expiration 1h
- Ne révèle pas si un email existe
- Rate limiting : 3 tentatives par 15 minutes
- Délai simulé pour éviter timing attacks

---

## 🏗️ Architecture en 3 Couches

### Couche 1 : Controllers (Présentation)

**Responsabilités:**
- ✅ Gestion des requêtes HTTP
- ✅ Validation des entrées utilisateur
- ✅ Affichage des vues (templates)
- ✅ Gestion des redirections
- ✅ Gestion de la session HTTP
- ❌ PAS de logique métier
- ❌ PAS d'accès direct à la DB

**Exemple:**
```python
@post("/register")
async def register(self, request: Request) -> Response:
    form_data = await request.form()
    username = form_data.get("username")
    email = form_data.get("email")
    password = form_data.get("password")

    # Appel au service
    user = await self.register_service.create_simple_user(username, email, password)

    return redirect(f"/auth/register/success?username={user.username}")
```

### Couche 2 : Services (Logique Métier)

**Responsabilités:**
- ✅ Logique métier
- ✅ Orchestration des opérations
- ✅ Validation métier
- ✅ Hash des mots de passe
- ✅ Génération/vérification des tokens
- ✅ Envoi d'emails (via EmailService)
- ❌ PAS d'accès direct à la DB
- ❌ PAS de gestion HTTP/session

**Exemple:**
```python
async def create_simple_user(self, username: str, email: str, password: str):
    # Vérifier unicité
    if await self.register_repo.user_exists(email):
        raise ValueError("Email déjà utilisé")

    # Hash mot de passe
    hashed_password = await self._async_hash_password(password)

    # Créer utilisateur via repository
    user = await self.register_repo.create_user(email, username, hashed_password, is_active=True)

    return user
```

### Couche 3 : Repositories (Accès aux Données)

**Responsabilités:**
- ✅ Accès à la base de données
- ✅ Requêtes SQL/ORM
- ✅ CRUD operations
- ❌ PAS de logique métier
- ❌ PAS de validation métier
- ❌ PAS de hash de mots de passe

**Exemple:**
```python
async def create_user(self, email: str, username: str, hashed_password: str, is_active: bool) -> User:
    user = User(
        email=email,
        username=username,
        password=hashed_password,
        is_active=is_active
    )

    self.db.add(user)
    await self.db.commit()
    await self.db.refresh(user)

    return user
```

---

## 🚀 Utilisation

### Importer les modules

```python
# Controllers
from app.controllers.auth import (
    RegisterController,
    RegisterVerifiedController,
    AuthController,
    ResetPasswordController,
)

# Services
from domain.auth import (
    RegisterService,
    RegisterVerifiedService,
    AuthService,
    ResetPasswordService,
)

# Repositories
from repositories.auth import (
    RegisterRepository,
    RegisterVerifiedRepository,
    AuthRepository,
    ResetPasswordRepository,
)
```

### Injection de dépendances

```python
def configure_services(services: ServiceCollection):
    # Repositories (scoped - une instance par requête)
    services.add_scoped(RegisterRepository)
    services.add_scoped(RegisterVerifiedRepository)
    services.add_scoped(AuthRepository)
    services.add_scoped(ResetPasswordRepository)

    # Services
    services.add_scoped(RegisterService)
    services.add_scoped(RegisterVerifiedService)
    services.add_scoped(AuthService)
    services.add_scoped(ResetPasswordService)

    # Controllers
    services.add_scoped(RegisterController)
    services.add_scoped(RegisterVerifiedController)
    services.add_scoped(AuthController)
    services.add_scoped(ResetPasswordController)
```

---

## 📝 Avantages de cette Architecture

### 1. Séparation des Responsabilités (SRP)
- Chaque couche a un rôle bien défini
- Facile à comprendre et maintenir

### 2. Testabilité
- Tests unitaires faciles (mock des dépendances)
- Tests d'intégration par couche

### 3. Réutilisabilité
- Services réutilisables (API REST + Web)
- Repositories réutilisables

### 4. Modularité
- Fonctionnalités isolées
- Facile d'ajouter/modifier

### 5. Maintenabilité
- Modifications localisées
- Code plus lisible

---

## 🔒 Sécurité

- **Hash bcrypt** pour les mots de passe
- **Tokens signés** avec itsdangerous
- **Rate limiting** sur endpoints sensibles
- **Protection énumération** des comptes
- **Expiration des tokens**
- **Validation** à tous les niveaux

---

## 📊 Flux Complets

### Inscription avec vérification email

```
1. GET /auth/register-verified → Formulaire
2. POST /auth/register-verified
   ↓
   RegisterVerifiedController
   ↓
   RegisterVerifiedService
   - Hash mot de passe
   - Créer utilisateur (inactif)
   - Envoyer email confirmation ✉️
   - Générer token
   - Envoyer email vérification ✉️
   ↓
   RegisterVerifiedRepository
   - Créer User en DB
   - Créer VerificationToken en DB

3. Utilisateur clique sur lien email
4. GET /auth/register-verified/verify-email/{token}
   ↓
   RegisterVerifiedController
   ↓
   RegisterVerifiedService
   - Vérifier token
   - Activer utilisateur
   - Envoyer email remerciement ✉️
   - Envoyer email bienvenue ✉️
   ↓
   RegisterVerifiedRepository
   - Activer User en DB
   - Marquer token comme utilisé

5. Redirection → /auth/login
```

---

**Date de création :** 2025-12-01
**Version :** 2.0 (avec Repositories)
