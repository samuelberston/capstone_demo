from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Use the same database URL as your application
DATABASE_URL = "postgresql://samuelberston@localhost/security_scan_db"
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

def run_migration():
    # Create a session
    session = Session()
    
    try:
        # Add columns to codeql_findings table using text() for raw SQL
        session.execute(text("""
        ALTER TABLE codeql_findings 
        ADD COLUMN IF NOT EXISTS code_context TEXT,
        ADD COLUMN IF NOT EXISTS analysis JSONB;
        """))
        
        # Commit the changes
        session.commit()
        print("Migration completed successfully!")
        
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

if __name__ == "__main__":
    try:
        run_migration()
    except Exception as e:
        print(f"Migration failed: {str(e)}") 