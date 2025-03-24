from sqlalchemy import create_engine
from models import Base

DATABASE_URL = "postgresql://samuelberston@localhost/security_scan_db"
engine = create_engine(DATABASE_URL)

def reset_database():
    # Drop all tables
    Base.metadata.drop_all(engine)
    
    # Create all tables with new schema
    Base.metadata.create_all(engine)
    
    print("Database has been wiped successfully!")

if __name__ == "__main__":
    reset_database() 