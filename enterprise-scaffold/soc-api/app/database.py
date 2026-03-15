import os
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

# PostgreSQL connection in asyncpg format
DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    "postgresql+asyncpg://postgres:postgres@localhost:5432/netforensics"
)

# Create the async engine
engine = create_async_engine(DATABASE_URL, echo=False)

# Create an asynchronous session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine, 
    class_=AsyncSession, 
    expire_on_commit=False
)

Base = declarative_base()

async def get_db():
    """Dependency to inject database sessions into HTTP endpoints"""
    async with AsyncSessionLocal() as session:
        yield session
