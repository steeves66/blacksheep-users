from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker

from app.settings import load_settings


settings = load_settings()
# Création du moteur async
engine = create_async_engine(
    settings.database.url,
    echo=settings.database.echo,  # Mettre à True pour voir les requêtes SQL en développement
    future=True,
)

# Factory pour créer des sessions async
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

async def get_session() -> AsyncSession:
    """
    Générateur de session de base de données pour l'injection de dépendances.
    """
    async with AsyncSessionLocal() as db_session:
        yield db_session
