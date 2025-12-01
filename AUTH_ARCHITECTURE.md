# Architecture Modulaire d'Authentification

Ce document décrit la nouvelle architecture modulaire pour les fonctionnalités d'authentification.

## 🎯 Objectif

Découper le code d'authentification en modules indépendants, chacun avec son propre contrôleur, service et templates.

## 📁 Structure

```
app/
├── controllers/
│   └── auth/
│       ├── __init__.py                           # Expose tous les contrôleurs
│       ├── register_controller.py                # Inscription simple
│       ├── register_verified_controller.py       # Inscription avec email
│       ├── login_controller.py                   # Connexion
│       ├── logout_controller.py                  # Déconnexion
│       └── reset_password_controller.py          # Réinitialisation
│
├── views/
│   └── auth/
│       ├── register/                             # Templates inscription simple
│       │   ├── register.jinja
│       │   └── success.jinja
│       ├── register_verified/                    # Templates inscription avec email
│       │   ├── register_verified.jinja
│       │   ├── success.jinja
│       │   ├── verify_error.jinja
│       │   ├── resend_verification.jinja
│       │   ├── resend_success.jinja
│       │   └── account_active.jinja
│       ├── login/                                # Templates connexion
│       │   ├── login.jinja
│       │   └── success.jinja
│       ├── logout/                               # Templates déconnexion
│       │   └── success.jinja
│       └── reset_password/                       # Templates réinitialisation
│           ├── forgot_password.jinja
│           ├── forgot_password_sent.jinja
│           ├── reset_password.jinja
│           ├── reset_password_expired.jinja
│           ├── reset_password_error.jinja
│           └── reset_password_success.jinja
│
domain/
└── auth/
    ├── __init__.py                               # Expose tous les services
    ├── register_service.py                       # Service inscription simple
    ├── register_verified_service.py              # Service inscription avec email
    ├── login_service.py                          # Service connexion
    └── reset_password_service.py                 # Service réinitialisation
```

## 🔧 Fonctionnalités

### 1. **Register Simple** (Inscription sans vérification email)

**Contrôleur:** `RegisterController`
**Service:** `RegisterService`
**Routes:**
- `GET  /auth/register` - Formulaire d'inscription
- `POST /auth/register` - Traiter l'inscription
- `GET  /auth/register/success` - Page de succès

**Caractéristiques:**
- L'utilisateur est actif immédiatement après inscription
- Pas d'envoi d'email
- Authentification instantanée possible

**Templates:**
- `app/views/auth/register/register.jinja` - Formulaire
- `app/views/auth/register/success.jinja` - Succès

---

### 2. **Register Verified** (Inscription avec vérification email)

**Contrôleur:** `RegisterVerifiedController`
**Service:** `RegisterVerifiedService`
**Routes:**
- `GET  /auth/register-verified` - Formulaire d'inscription
- `POST /auth/register-verified` - Traiter l'inscription
- `GET  /auth/register-verified/verify-email/{token}` - Vérifier l'email
- `GET  /auth/register-verified/resend-verification` - Formulaire de renvoi
- `POST /auth/register-verified/resend-verification` - Renvoyer l'email
- `GET  /auth/register-verified/account-active` - Compte déjà actif

**Caractéristiques:**
- L'utilisateur est créé mais inactif
- Email de vérification envoyé
- Token de vérification avec expiration
- Possibilité de renvoyer l'email

**Templates:**
- `app/views/auth/register_verified/register_verified.jinja` - Formulaire
- `app/views/auth/register_verified/success.jinja` - Succès inscription
- `app/views/auth/register_verified/verify_error.jinja` - Erreur vérification
- `app/views/auth/register_verified/resend_verification.jinja` - Formulaire renvoi
- `app/views/auth/register_verified/resend_success.jinja` - Succès renvoi
- `app/views/auth/register_verified/account_active.jinja` - Compte déjà actif

---

### 3. **Login** (Connexion)

**Contrôleur:** `LoginController`
**Service:** `LoginService`
**Routes:**
- `GET  /auth/login` - Formulaire de connexion
- `POST /auth/login` - Traiter la connexion
- `GET  /auth/login/success` - Page de succès

**Caractéristiques:**
- Authentification par email ou username
- Vérification du mot de passe bcrypt
- Vérification que le compte est actif
- Création de session utilisateur
- Rate limiting (5 tentatives par 5 minutes)

**Templates:**
- `app/views/auth/login/login.jinja` - Formulaire
- `app/views/auth/login/success.jinja` - Succès

---

### 4. **Logout** (Déconnexion)

**Contrôleur:** `LogoutController`
**Service:** Aucun (logique simple)
**Routes:**
- `GET /auth/logout` - Déconnecter l'utilisateur
- `GET /auth/logout/success` - Page de succès

**Caractéristiques:**
- Suppression des données de session
- Redirection vers page de succès

**Templates:**
- `app/views/auth/logout/success.jinja` - Succès

---

### 5. **Reset Password** (Réinitialisation du mot de passe)

**Contrôleur:** `ResetPasswordController`
**Service:** `ResetPasswordService`
**Routes:**
- `GET  /auth/reset-password/forgot-password` - Formulaire demande reset
- `POST /auth/reset-password/forgot-password` - Traiter demande reset
- `GET  /auth/reset-password/reset/{token}` - Formulaire nouveau mot de passe
- `POST /auth/reset-password/reset/{token}` - Traiter nouveau mot de passe
- `GET  /auth/reset-password/success` - Page de succès

**Caractéristiques:**
- Token de réinitialisation avec expiration (1h)
- Email avec lien de réinitialisation
- Validation du nouveau mot de passe
- Sécurité : ne révèle pas si un email existe
- Rate limiting (3 tentatives par 15 minutes)

**Templates:**
- `app/views/auth/reset_password/forgot_password.jinja` - Demande reset
- `app/views/auth/reset_password/forgot_password_sent.jinja` - Email envoyé
- `app/views/auth/reset_password/reset_password.jinja` - Nouveau mot de passe
- `app/views/auth/reset_password/reset_password_expired.jinja` - Token expiré
- `app/views/auth/reset_password/reset_password_error.jinja` - Erreur
- `app/views/auth/reset_password/reset_password_success.jinja` - Succès

---

## 🚀 Utilisation

### Importer les contrôleurs

```python
from app.controllers.auth import (
    RegisterController,
    RegisterVerifiedController,
    LoginController,
    LogoutController,
    ResetPasswordController,
)
```

### Importer les services

```python
from domain.auth import (
    RegisterService,
    RegisterVerifiedService,
    LoginService,
    ResetPasswordService,
)
```

### Injection de dépendances

Les contrôleurs reçoivent leurs services via injection de dépendances :

```python
# Dans app/main.py ou le fichier de configuration DI

def configure_services(services: ServiceCollection):
    # Services
    services.add_scoped(RegisterService)
    services.add_scoped(RegisterVerifiedService)
    services.add_scoped(LoginService)
    services.add_scoped(ResetPasswordService)

    # Contrôleurs
    services.add_scoped(RegisterController)
    services.add_scoped(RegisterVerifiedController)
    services.add_scoped(LoginController)
    services.add_scoped(LogoutController)
    services.add_scoped(ResetPasswordController)
```

---

## 📝 Principes de conception

### Séparation des responsabilités

#### Contrôleurs
- Gestion des routes HTTP
- Validation des entrées utilisateur
- Affichage des vues (templates)
- Gestion des redirections
- Gestion de la session

#### Services
- Logique métier
- Orchestration des opérations
- Validation métier
- Génération et vérification des tokens
- Hash des mots de passe

#### Repositories
- Accès à la base de données
- Requêtes SQL/ORM
- CRUD operations

### Avantages de cette architecture

1. **Modularité** : Chaque fonctionnalité est isolée
2. **Maintenabilité** : Modifications localisées
3. **Testabilité** : Tests unitaires facilités
4. **Réutilisabilité** : Services réutilisables
5. **Clarté** : Code plus lisible et organisé

---

## 🔒 Sécurité

- **Rate limiting** sur les endpoints sensibles
- **Tokens signés** avec itsdangerous
- **Hash bcrypt** pour les mots de passe
- **Expiration des tokens** (vérification email : variable, reset password : 1h)
- **Protection contre l'énumération** des comptes (reset password)
- **Validation des entrées** à tous les niveaux

---

## 🧪 Tests

Structure recommandée pour les tests :

```
tests/
├── controllers/
│   └── auth/
│       ├── test_register_controller.py
│       ├── test_register_verified_controller.py
│       ├── test_login_controller.py
│       ├── test_logout_controller.py
│       └── test_reset_password_controller.py
│
└── services/
    └── auth/
        ├── test_register_service.py
        ├── test_register_verified_service.py
        ├── test_login_service.py
        └── test_reset_password_service.py
```

---

## 📊 Flux utilisateur

### Inscription simple
1. `GET /auth/register` → Affiche le formulaire
2. `POST /auth/register` → Crée l'utilisateur (actif)
3. Redirection → `/auth/register/success`
4. L'utilisateur peut se connecter immédiatement

### Inscription avec vérification
1. `GET /auth/register-verified` → Affiche le formulaire
2. `POST /auth/register-verified` → Crée l'utilisateur (inactif) + envoie email
3. Utilisateur clique sur le lien dans l'email
4. `GET /auth/register-verified/verify-email/{token}` → Active le compte
5. Redirection → `/auth/login`

### Connexion
1. `GET /auth/login` → Affiche le formulaire
2. `POST /auth/login` → Authentifie l'utilisateur
3. Crée la session
4. Redirection → `/auth/login/success`

### Réinitialisation
1. `GET /auth/reset-password/forgot-password` → Formulaire email
2. `POST /auth/reset-password/forgot-password` → Envoie email
3. Utilisateur clique sur le lien
4. `GET /auth/reset-password/reset/{token}` → Formulaire nouveau mot de passe
5. `POST /auth/reset-password/reset/{token}` → Change le mot de passe
6. Redirection → `/auth/reset-password/success`

---

## 🔄 Migration depuis l'ancien code

L'ancien code se trouve dans :
- `app/controllers/user_controller.py` (ancien contrôleur monolithique)
- `domain/user_service.py` (ancien service monolithique)

La nouvelle architecture est **compatible** avec l'ancienne. Vous pouvez :
1. Utiliser les nouveaux contrôleurs en parallèle
2. Migrer progressivement les routes
3. Supprimer l'ancien code une fois la migration terminée

---

## 📚 Documentation des API

Voir la documentation OpenAPI générée automatiquement par BlackSheep sur `/docs`.

---

**Date de création :** 2025-12-01
**Auteur :** Refactorisation modulaire de l'authentification
