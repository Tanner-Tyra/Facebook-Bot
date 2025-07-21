from sqlalchemy import create_engine, Column, String, Text, Integer, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(String, primary_key=True)
    first_name = Column(String)
    last_name = Column(String)
    approved = Column(String)  # "yes" or "no"
    created_at = Column(DateTime, default=datetime.now(timezone.utc))
    remove_from_display = Column(Boolean, default=False)

class Message(Base):
    __tablename__ = 'messages'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sender_id = Column(String)
    role = Column(String)  # "user" or "assistant"
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.now(timezone.utc))

# SQLite engine (swap for PostgreSQL/MySQL if needed)
engine = create_engine('sqlite:///chatbot.db', echo=False)
SessionLocal = sessionmaker(bind=engine)

# Create tables
Base.metadata.create_all(engine)
