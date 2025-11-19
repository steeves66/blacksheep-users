"""
Script d'initialisation du système RBAC v2

Ce script crée les rôles et permissions par défaut.

Usage:
    python scripts/init_rbac_v2.py
"""

import asyncio
import logging
from dbsession import AsyncSessionLocal
from repositories.user_repository import UserRepository
from app.settings import load_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


settings = load_settings()

# Les mêmes permissions que la v1
DEFAULT_PERMISSIONS = [
    # Permissions utilisateurs
    {"name": "user.create", "display_name": "Créer des utilisateurs", "resource": "user", "action": "create", "description": "Permet de créer de nouveaux comptes utilisateurs", "is_system": True},
    {"name": "user.read", "display_name": "Voir les utilisateurs", "resource": "user", "action": "read", "description": "Permet de consulter les profils utilisateurs", "is_system": True},
    {"name": "user.update", "display_name": "Modifier les utilisateurs", "resource": "user", "action": "update", "description": "Permet de modifier les comptes utilisateurs", "is_system": True},
    {"name": "user.delete", "display_name": "Supprimer les utilisateurs", "resource": "user", "action": "delete", "description": "Permet de supprimer des comptes utilisateurs", "is_system": True},
    {"name": "user.ban", "display_name": "Bannir des utilisateurs", "resource": "user", "action": "ban", "description": "Permet de bannir des utilisateurs", "is_system": True},
    
    # Permissions posts/articles
    {"name": "post.create", "display_name": "Créer des posts", "resource": "post", "action": "create", "description": "Permet de créer de nouveaux posts", "is_system": True},
    {"name": "post.read", "display_name": "Voir les posts", "resource": "post", "action": "read", "description": "Permet de consulter les posts", "is_system": True},
    {"name": "post.update", "display_name": "Modifier des posts", "resource": "post", "action": "update", "description": "Permet de modifier ses propres posts", "is_system": True},
    {"name": "post.update_any", "display_name": "Modifier tous les posts", "resource": "post", "action": "update_any", "description": "Permet de modifier n'importe quel post", "is_system": True},
    {"name": "post.delete", "display_name": "Supprimer des posts", "resource": "post", "action": "delete", "description": "Permet de supprimer ses propres posts", "is_system": True},
    {"name": "post.delete_any", "display_name": "Supprimer tous les posts", "resource": "post", "action": "delete_any", "description": "Permet de supprimer n'importe quel post", "is_system": True},
    {"name": "post.publish", "display_name": "Publier des posts", "resource": "post", "action": "publish", "description": "Permet de publier des posts", "is_system": True},
    
    # Permissions commentaires
    {"name": "comment.create", "display_name": "Créer des commentaires", "resource": "comment", "action": "create", "description": "Permet de commenter", "is_system": True},
    {"name": "comment.moderate", "display_name": "Modérer les commentaires", "resource": "comment", "action": "moderate", "description": "Permet de modérer/supprimer les commentaires", "is_system": True},
    
    # Permissions rôles et permissions
    {"name": "role.manage", "display_name": "Gérer les rôles", "resource": "role", "action": "manage", "description": "Permet de créer/modifier/supprimer des rôles", "is_system": True},
    {"name": "permission.manage", "display_name": "Gérer les permissions", "resource": "permission", "action": "manage", "description": "Permet de créer/modifier/supprimer des permissions", "is_system": True},
    
    # Permissions système
    {"name": "settings.manage", "display_name": "Gérer les paramètres", "resource": "settings", "action": "manage", "description": "Permet d'accéder aux paramètres système", "is_system": True},
    {"name": "logs.view", "display_name": "Voir les logs", "resource": "logs", "action": "view", "description": "Permet de consulter les logs système", "is_system": True},
    {"name": "analytics.view", "display_name": "Voir les analytics", "resource": "analytics", "action": "view", "description": "Permet de consulter les statistiques", "is_system": True},
]


DEFAULT_ROLES = [
    {
        "name": "super_admin",
        "display_name": "Super Administrateur",
        "description": "Accès complet au système, tous les droits",
        "priority": 1000,
        "is_system": True,
        "is_default": False,
        "permissions": [
            "user.create", "user.read", "user.update", "user.delete", "user.ban",
            "post.create", "post.read", "post.update", "post.update_any",
            "post.delete", "post.delete_any", "post.publish",
            "comment.create", "comment.moderate",
            "role.manage", "permission.manage",
            "settings.manage", "logs.view", "analytics.view",
        ],
    },
    {
        "name": "admin",
        "display_name": "Administrateur",
        "description": "Administration générale du site",
        "priority": 500,
        "is_system": True,
        "is_default": False,
        "permissions": [
            "user.read", "user.update", "user.ban",
            "post.create", "post.read", "post.update_any", "post.delete_any", "post.publish",
            "comment.create", "comment.moderate",
            "analytics.view", "logs.view",
        ],
    },
    {
        "name": "moderator",
        "display_name": "Modérateur",
        "description": "Modération du contenu et des utilisateurs",
        "priority": 100,
        "is_system": True,
        "is_default": False,
        "permissions": [
            "user.read", "user.ban",
            "post.read", "post.update_any", "post.delete_any",
            "comment.moderate",
        ],
    },
    {
        "name": "author",
        "display_name": "Auteur",
        "description": "Peut créer et publier du contenu",
        "priority": 50,
        "is_system": True,
        "is_default": False,
        "permissions": [
            "post.create", "post.read", "post.update", "post.delete", "post.publish",
            "comment.create",
            "analytics.view",
        ],
    },
    {
        "name": "user",
        "display_name": "Utilisateur",
        "description": "Utilisateur standard avec permissions de base",
        "priority": 10,
        "is_system": True,
        "is_default": True,
        "permissions": [
            "post.read",
            "post.create",
            "post.update",
            "post.delete",
            "comment.create",
        ],
    },
    {
        "name": "guest",
        "display_name": "Invité",
        "description": "Visiteur avec accès en lecture seule",
        "priority": 1,
        "is_system": True,
        "is_default": False,
        "permissions": ["post.read"],
    },
]


async def init_permissions(rbac_repo: UserRepository) -> dict:
    """Créer toutes les permissions"""
    permissions_map = {}
    logger.info("Creating permissions...")
    
    for perm_data in DEFAULT_PERMISSIONS:
        existing_perm = await rbac_repo.get_permission_by_name(perm_data["name"])
        
        if existing_perm:
            logger.info(f"  ✓ Permission exists: {perm_data['name']}")
            permissions_map[perm_data["name"]] = existing_perm
        else:
            permission = await rbac_repo.create_permission(**perm_data)
            permissions_map[perm_data["name"]] = permission
            logger.info(f"  + Permission created: {perm_data['name']}")
    
    logger.info(f"✅ {len(permissions_map)} permissions ready")
    return permissions_map


async def init_roles(rbac_repo: UserRepository, permissions_map: dict) -> dict:
    """Créer tous les rôles"""
    roles_map = {}
    logger.info("Creating roles...")
    
    for role_data in DEFAULT_ROLES:
        permission_names = role_data.pop("permissions", [])
        
        existing_role = await rbac_repo.get_role_by_name(role_data["name"])
        
        if existing_role:
            logger.info(f"  ✓ Role exists: {role_data['name']}")
            roles_map[role_data["name"]] = existing_role
        else:
            role = await rbac_repo.create_role(**role_data)
            roles_map[role_data["name"]] = role
            logger.info(f"  + Role created: {role_data['name']}")
        
        role = roles_map[role_data["name"]]
        
        for perm_name in permission_names:
            if perm_name in permissions_map:
                permission = permissions_map[perm_name]
                await rbac_repo.assign_permission_to_role(role.id, permission.id)
        
        logger.info(f"    → {len(permission_names)} permissions assigned")
    
    logger.info(f"✅ {len(roles_map)} roles ready")
    return roles_map


async def display_summary(rbac_repo: UserRepository):
    """Afficher un résumé"""
    all_roles = await rbac_repo.get_all_roles()
    all_permissions = await rbac_repo.get_all_permissions()
    
    logger.info("\n" + "="*60)
    logger.info("RBAC V2 SYSTEM SUMMARY")
    logger.info("="*60)
    logger.info(f"\n📊 Total Permissions: {len(all_permissions)}")
    logger.info(f"📊 Total Roles: {len(all_roles)}")
    logger.info("\n⭐ NOUVEAUTÉS V2:")
    logger.info("  - Table user_permissions (permissions directes)")
    logger.info("  - Permissions temporaires avec expiration")
    logger.info("  - Raison d'attribution pour audit")
    logger.info("  - Distinction permissions directes / via rôles")
    logger.info("\n🎭 ROLES:\n")
    
    for role in sorted(all_roles, key=lambda r: r.priority, reverse=True):
        perms = await rbac_repo.get_role_permissions(role.id)
        user_count = await rbac_repo.get_role_user_count(role.id)
        
        logger.info(f"  {role.display_name} ({role.name})")
        logger.info(f"    Priority: {role.priority}, Users: {user_count}, Default: {'✓' if role.is_default else '✗'}")
        logger.info(f"    Permissions: {len(perms)}")
        logger.info("")
    
    logger.info("="*60)


async def main():
    """Fonction principale"""
    logger.info("🚀 Starting RBAC v2 initialization...")
    
    async with AsyncSessionLocal() as db:
        rbac_repo = UserRepository(db, settings)
        
        permissions_map = await init_permissions(rbac_repo)
        roles_map = await init_roles(rbac_repo, permissions_map)
        await display_summary(rbac_repo)
    
    logger.info("\n✅ RBAC v2 initialization completed!")
    logger.info("\n📝 Next steps:")
    logger.info("  1. Assign default role to existing users")
    logger.info("  2. Test permissions: python scripts/test_rbac_v2.py")
    logger.info("  3. Grant direct permissions via API or admin panel")


if __name__ == "__main__":
    asyncio.run(main())
