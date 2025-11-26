"""
Script manuel pour tester les décorateurs de rate limiting.

Ce script suppose que le serveur BlackSheep tourne (ex: `uvicorn app.main:app --reload`)
et que la base de données est accessible. Il nettoie la table `rate_limits` avant
chaque scénario puis envoie (limit + 1) requêtes pour vérifier qu'un HTTP 429 est
retourné lorsque la limite est dépassée.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Callable, Dict, Any
from uuid import uuid4

import httpx
from sqlalchemy import delete

# S'assurer que la racine du projet est dans sys.path pour les imports locaux
ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dbsession import AsyncSessionLocal           
from model.user import RateLimit

BASE_URL = "http://localhost:44777"


async def reset_rate_limits() -> None:
    """Supprime toutes les entrées de rate limit (utile pour les tests manuels)."""
    async with AsyncSessionLocal() as db:
        await db.execute(delete(RateLimit))
        await db.commit()


async def hammer_endpoint(
    client: httpx.AsyncClient,
    name: str,
    method: str,
    path: str,
    limit: int,
    payload_factory: Callable[[int], Dict[str, Any]] | None = None,
) -> None:
    print(f"\n=== Test rate limit: {name} ({method.upper()} {path}) ===")
    await reset_rate_limits()

    for attempt in range(1, limit + 2):
        data = payload_factory(attempt) if payload_factory else None
        response = await client.request(method, f"{BASE_URL}{path}", data=data)
        print(f"Attempt {attempt}: status={response.status_code}")
        if response.status_code == 429:
            print("-> Rate limit atteint comme attendu ✅")
            break
    else:
        print("⚠️  Aucun HTTP 429 reçu, vérifier la configuration du décorateur.")


async def main() -> None:
    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        await hammer_endpoint(
            client,
            name="Register",
            method="post",
            path="/users/register",
            limit=5,
            payload_factory=lambda i: {
                "username": f"testuser_{uuid4().hex}",
                "email": f"test_{uuid4().hex}@example.com",
                "password": "Password123!",
                "confirm_password": "Password123!",
            },
        )

        await hammer_endpoint(
            client,
            name="Login",
            method="post",
            path="/users/login",
            limit=5,
            payload_factory=lambda i: {
                "identifier": "unknown@example.com",
                "password": "wrong-password",
            },
        )

        await hammer_endpoint(
            client,
            name="Forgot Password",
            method="post",
            path="/users/forgot-password",
            limit=3,
            payload_factory=lambda i: {"email": "unknown@example.com"},
        )

        await hammer_endpoint(
            client,
            name="Session Test",
            method="get",
            path="/session/test",
            limit=10,
        )


if __name__ == "__main__":
    asyncio.run(main())

