import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from dotenv import load_dotenv
from config.database import engine, Base
# Import all models so Base.metadata knows about them
from models import User

load_dotenv()

def init_db():
    # 1. Get connection details from .env
    user = os.getenv("POSTGRES_USER", "postgres")
    password = os.getenv("POSTGRES_PASSWORD", "1234")
    host = os.getenv("POSTGRES_HOST", "localhost")
    port = os.getenv("POSTGRES_PORT", "5432")
    dbname = os.getenv("POSTGRES_DB", "medisecure")

    print(f"Checking database: {dbname}...")

    try:
        # 2. Connect to the default 'postgres' database to create the new one
        con = psycopg2.connect(
            dbname="postgres",
            user=user,
            host=host,
            password=password,
            port=port
        )
        con.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = con.cursor()

        # 3. Check if database exists
        cursor.execute(f"SELECT 1 FROM pg_catalog.pg_database WHERE datname = '{dbname}'")
        exists = cursor.fetchone()

        if not exists:
            print(f"Database '{dbname}' does not exist. Creating...")
            cursor.execute(f"CREATE DATABASE {dbname}")
            print(f"Database '{dbname}' created successfully!")
        else:
            print(f"Database '{dbname}' already exists.")

        cursor.close()
        con.close()

        # 4. Create Tables using SQLAlchemy
        print("Creating tables...")
        Base.metadata.create_all(bind=engine)
        print("Tables created successfully!")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    init_db()