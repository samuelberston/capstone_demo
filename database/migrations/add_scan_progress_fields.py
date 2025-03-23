from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import os
import sys
from pathlib import Path
import time
import logging
from sqlalchemy.exc import OperationalError

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Add the parent directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from database.models import Base

# Get database URL from environment variable or use default
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://samuelberston@localhost/security_scan_db')

def create_db_connection():
    logger.info(f"Attempting to connect to database at {DATABASE_URL}")
    try:
        engine = create_engine(DATABASE_URL, connect_args={'connect_timeout': 10})
        # Test the connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return engine
    except Exception as e:
        logger.error(f"Failed to connect to database: {str(e)}")
        print("Please check if:")
        print("1. PostgreSQL is running")
        print("2. The database 'security_scan_db' exists")
        print("3. Your user has the correct permissions")
        sys.exit(1)

def check_table_exists(session):
    try:
        result = session.execute(text("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'scans'
            );
        """))
        exists = result.scalar()
        logger.info(f"Table 'scans' exists: {exists}")
        return exists
    except Exception as e:
        logger.error(f"Error checking if table exists: {str(e)}")
        return False

def check_table_locks(session):
    try:
        result = session.execute(text("""
            SELECT blocked_locks.pid AS blocked_pid,
                   blocked_activity.usename AS blocked_user,
                   blocking_locks.pid AS blocking_pid,
                   blocking_activity.usename AS blocking_user,
                   blocked_activity.query AS blocked_statement,
                   blocking_activity.query AS current_statement_in_blocking_process
            FROM pg_catalog.pg_locks blocked_locks
            JOIN pg_catalog.pg_stat_activity blocked_activity ON blocked_activity.pid = blocked_locks.pid
            JOIN pg_catalog.pg_locks blocking_locks ON blocking_locks.locktype = blocked_locks.locktype
            JOIN pg_catalog.pg_stat_activity blocking_activity ON blocking_activity.pid = blocking_locks.pid
            WHERE NOT blocked_locks.granted
            AND blocked_locks.relation = 'scans'::regclass;
        """))
        locks = result.fetchall()
        if locks:
            logger.warning("Found locks on scans table:")
            for lock in locks:
                logger.warning(f"Blocked PID: {lock[0]}, Blocking PID: {lock[2]}")
        return len(locks) > 0
    except Exception as e:
        logger.error(f"Error checking table locks: {str(e)}")
        return False

def add_column_with_retry(session, column_name, column_type, max_retries=3):
    for attempt in range(max_retries):
        try:
            # First check if column exists
            result = session.execute(text(f"""
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_name = 'scans' 
                    AND column_name = '{column_name}'
                );
            """))
            if result.scalar():
                logger.info(f"Column {column_name} already exists")
                return True

            # Check for locks before proceeding
            if check_table_locks(session):
                logger.warning("Table is locked, waiting before retry...")
                time.sleep(5)  # Wait longer if table is locked
                continue

            # Try to add the column with a timeout and lock timeout
            session.execute(text(f"""
                SET statement_timeout = '30s';
                SET lock_timeout = '30s';
                ALTER TABLE scans 
                ADD COLUMN {column_name} {column_type};
            """))
            logger.info(f"Successfully added column {column_name}")
            return True
        except OperationalError as e:
            if attempt < max_retries - 1:
                logger.warning(f"Attempt {attempt + 1} failed: {str(e)}. Retrying...")
                time.sleep(2)  # Wait before retrying
                session.rollback()
            else:
                logger.error(f"Failed to add column {column_name} after {max_retries} attempts: {str(e)}")
                raise
    return False

def upgrade():
    engine = create_db_connection()
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        logger.info("Starting upgrade process...")
        
        # First check if the table exists
        if not check_table_exists(session):
            logger.error("Table 'scans' does not exist!")
            return
            
        # Check if columns already exist
        logger.info("Checking existing columns...")
        result = session.execute(text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'scans';
        """))
        existing_columns = [row[0] for row in result]
        logger.info(f"Existing columns: {existing_columns}")
        
        # Add columns one by one with error handling
        columns_to_add = [
            ('current_step', 'VARCHAR(100)'),
            ('progress_percentage', 'INTEGER DEFAULT 0'),
            ('status_message', 'TEXT'),
            ('error_message', 'TEXT')
        ]
        
        for column_name, column_type in columns_to_add:
            if column_name not in existing_columns:
                logger.info(f"Adding column {column_name}...")
                try:
                    add_column_with_retry(session, column_name, column_type)
                except Exception as e:
                    logger.error(f"Error adding column {column_name}: {str(e)}")
                    session.rollback()
                    raise
            else:
                logger.info(f"Column {column_name} already exists")
        
        session.commit()
        logger.info("Successfully completed upgrade")
    except Exception as e:
        session.rollback()
        logger.error(f"Error during migration: {str(e)}")
        raise
    finally:
        session.close()

def downgrade():
    engine = create_db_connection()
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        logger.info("Starting downgrade process...")
        
        # Check if table exists
        if not check_table_exists(session):
            logger.error("Table 'scans' does not exist!")
            return
            
        # Remove columns one by one
        columns_to_remove = [
            'current_step',
            'progress_percentage',
            'status_message',
            'error_message'
        ]
        
        for column_name in columns_to_remove:
            logger.info(f"Attempting to remove column {column_name}...")
            try:
                # Check for locks before proceeding
                if check_table_locks(session):
                    logger.warning("Table is locked, waiting before retry...")
                    time.sleep(5)
                    continue

                session.execute(text(f"""
                    SET statement_timeout = '30s';
                    SET lock_timeout = '30s';
                    ALTER TABLE scans 
                    DROP COLUMN IF EXISTS {column_name};
                """))
                logger.info(f"Successfully removed column {column_name}")
            except Exception as e:
                logger.error(f"Error removing column {column_name}: {str(e)}")
                session.rollback()
                raise
        
        session.commit()
        logger.info("Successfully completed downgrade")
    except Exception as e:
        session.rollback()
        logger.error(f"Error during rollback: {str(e)}")
        raise
    finally:
        session.close()

if __name__ == "__main__":
    logger.info("Starting database migration...")
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "downgrade":
            downgrade()
        else:
            upgrade()
        logger.info("Migration completed successfully.")
    except Exception as e:
        logger.error(f"Migration failed: {str(e)}")
        sys.exit(1) 