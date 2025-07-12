from sqlalchemy import create_engine, MetaData, text, event
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, AsyncEngine
import psycopg2
from psycopg2 import sql

credentials = "postgresql://postgres:postgres@localhost:5432/"
#credentials = "postgresql://postgres:gactivos@gbd-c:5432/"

# engine = create_engine("postgresql://postgres:gactivos@gbd-c:5432/gestion_activos")
engine = create_engine("postgresql://postgres:admin@localhost:5432/desafio_fintech") #Dany
#engine = create_engine(credentials + "gestion_activos")

SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def conexion(db: Session, companyId: int):
    print("entro a conexion")

    query = text("SELECT name_db FROM compania WHERE id = :company_id")
    result = db.execute(query, {"company_id": companyId})
    db_name = result.scalar()  # Obtiene el primer valor del primer resultado

    db.close()

    print("db_name: ", db_name)
    if (db_name is None):
        yield None
        return

    engine = create_engine(credentials + db_name)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()
