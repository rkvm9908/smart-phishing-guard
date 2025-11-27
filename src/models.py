
from sqlalchemy import Column, Integer, String, Float, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime, timezone 
from werkzeug.security import generate_password_hash, check_password_hash

# Base class for declarative class definitions
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128))
    is_admin = Column(Boolean, default=False)
    reset_otp = Column(String(6), nullable=True, default=None)
    otp_expiry = Column(DateTime, nullable=True, default=None)
    # Relationships
    logs = relationship("URLLog", back_populates="user")
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class URLLog(Base):
    __tablename__ = 'url_logs'
    
    id = Column(Integer, primary_key=True)
    # user_id can be null if the scan is performed by a guest
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True) 
    url = Column(String(512), nullable=False)
    
    # MODIFIED: Use datetime.now(timezone.utc) for timezone-aware storage in UTC
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc)) 
    
    # ML Prediction fields
    prediction = Column(String(16))
    prob_phishing = Column(Float)
    safety_score = Column(Float)
    
    # Stores features as a JSON string
    features = Column(String) 
    
    # Relationship to User
    user = relationship("User", back_populates="logs")

    def __repr__(self):
        return f'<URLLog {self.id} | {self.url}>'