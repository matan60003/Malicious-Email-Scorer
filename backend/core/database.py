from sqlmodel import SQLModel, create_engine
import logging

logger = logging.getLogger(__name__)

# Using an absolute path for local MVP testing or a local file
sqlite_file_name = "data.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

# Enable connect_args check_same_thread=False for SQLite in FastAPI (avoids thread issues)
engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})


def create_db_and_tables():
    logger.info("Creating database tables...")
    SQLModel.metadata.create_all(engine)
    logger.info("Database tables created successfully.")
