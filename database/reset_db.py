from sqlalchemy import create_engine
from database.models import Base

# Create database connection
engine = create_engine('postgresql://samuelberston@localhost/security_scan_db')

# This will drop all tables
Base.metadata.drop_all(engine)

# Optional: Recreate empty tables
Base.metadata.create_all(engine)

print("Database has been wiped successfully!") 