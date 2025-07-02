from utils.database import engine
from model.models import Base
from sqlalchemy import text

def drop_all_tables():
    """Drop all existing tables to start fresh"""
    try:
        with engine.connect() as connection:
            # Start transaction
            trans = connection.begin()
            
            try:
                # Get database type
                db_type = engine.dialect.name
                print(f"Database type: {db_type}")
                
                if db_type == 'postgresql':
                    # For PostgreSQL
                    print("Dropping all tables (PostgreSQL)...")
                    connection.execute(text("DROP SCHEMA public CASCADE"))
                    connection.execute(text("CREATE SCHEMA public"))
                    connection.execute(text("GRANT ALL ON SCHEMA public TO postgres"))
                    connection.execute(text("GRANT ALL ON SCHEMA public TO public"))
                    
                elif db_type == 'sqlite':
                    # For SQLite - get all table names and drop them
                    print("Dropping all tables (SQLite)...")
                    result = connection.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
                    tables = [row[0] for row in result.fetchall()]
                    
                    for table in tables:
                        if table != 'sqlite_sequence':  # Don't drop SQLite system table
                            connection.execute(text(f"DROP TABLE IF EXISTS {table}"))
                            print(f"  Dropped table: {table}")
                            
                else:
                    # For MySQL and other databases
                    print("Dropping all tables (MySQL/Other)...")
                    connection.execute(text("SET FOREIGN_KEY_CHECKS = 0"))
                    
                    # Get all table names
                    result = connection.execute(text("SHOW TABLES"))
                    tables = [row[0] for row in result.fetchall()]
                    
                    # Drop all tables
                    for table in tables:
                        connection.execute(text(f"DROP TABLE IF EXISTS {table}"))
                        print(f"  Dropped table: {table}")
                    
                    connection.execute(text("SET FOREIGN_KEY_CHECKS = 1"))
                
                # Commit the transaction
                trans.commit()
                print("✅ All tables dropped successfully!")
                return True
                
            except Exception as e:
                trans.rollback()
                print(f"❌ Error dropping tables: {e}")
                return False
                
    except Exception as e:
        print(f"❌ Failed to connect to database: {e}")
        return False

def create_all_tables():
    """Create all tables from models"""
    try:
        print("Creating all tables from models...")
        Base.metadata.create_all(bind=engine)
        print("✅ All tables created successfully!")
        return True
    except Exception as e:
        print(f"❌ Error creating tables: {e}")
        return False

def show_table_info():
    """Show information about created tables"""
    try:
        with engine.connect() as connection:
            db_type = engine.dialect.name
            
            if db_type == 'postgresql':
                result = connection.execute(text("""
                    SELECT table_name, column_name, data_type, is_nullable
                    FROM information_schema.columns 
                    WHERE table_schema = 'public'
                    ORDER BY table_name, ordinal_position
                """))
                
                current_table = None
                for row in result.fetchall():
                    if row[0] != current_table:
                        current_table = row[0]
                        print(f"\n📋 Table: {current_table}")
                    print(f"  └─ {row[1]} ({row[2]}) - {'NULL' if row[3] == 'YES' else 'NOT NULL'}")
                    
            elif db_type == 'sqlite':
                # Get all table names
                result = connection.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))
                tables = [row[0] for row in result.fetchall()]
                
                for table in tables:
                    print(f"\n📋 Table: {table}")
                    table_info = connection.execute(text(f"PRAGMA table_info({table})"))
                    for row in table_info.fetchall():
                        nullable = "NULL" if row[3] == 0 else "NOT NULL"
                        print(f"  └─ {row[1]} ({row[2]}) - {nullable}")
                        
            else:
                # For MySQL
                result = connection.execute(text("SHOW TABLES"))
                tables = [row[0] for row in result.fetchall()]
                
                for table in tables:
                    print(f"\n📋 Table: {table}")
                    table_info = connection.execute(text(f"DESCRIBE {table}"))
                    for row in table_info.fetchall():
                        nullable = "NULL" if row[2] == 'YES' else "NOT NULL"
                        print(f"  └─ {row[0]} ({row[1]}) - {nullable}")
                        
    except Exception as e:
        print(f"❌ Error showing table info: {e}")

def create_default_admin():
    """Create default admin user during migration"""
    try:
        print("Creating default admin user...")
        
        # Import required modules
        from model.models import User
        from helper.auth import hash_password
        from utils.database import SessionLocal
        
        # Create database session
        db = SessionLocal()
        
        try:
            # Check if admin user already exists
            existing_admin = db.query(User).filter(
                (User.username == "admin") | (User.role == "admin")
            ).first()
            
            if existing_admin:
                print(f"  ⚠️  Admin user already exists: {existing_admin.username}")
                return True
            
            # Create default admin user
            admin_user = User(
                username="admin",
                email="admin@comot.in",
                password=hash_password("admin234"),
                role="admin"
            )
            
            db.add(admin_user)
            db.commit()
            
            print("  ✅ Default admin user created successfully!")
            print(f"     Username: admin")
            print(f"     Email: admin@comot.in")
            print(f"     Password: admin234")
            print(f"     Role: admin")
            print("\n  🚨 IMPORTANT: Change the default password after first login!")
            
            return True
            
        except Exception as e:
            db.rollback()
            print(f"  ❌ Error creating admin user: {e}")
            return False
            
        finally:
            db.close()
            
    except Exception as e:
        print(f"❌ Failed to create admin user: {e}")
        return False

def main():
    """Main migration function"""
    print("🚀 Starting complete database migration...")
    print("This will drop ALL existing tables and recreate them from scratch.")
    print("⚠️  WARNING: All existing data will be lost!")
    
    # Ask for confirmation in production
    import os
    env = os.getenv('ENVIRONMENT', 'development')
    
    if env.lower() in ['production', 'prod']:
        confirm = input("\n❗ You are in PRODUCTION mode! Are you sure? (type 'YES' to continue): ")
        if confirm != 'YES':
            print("❌ Migration cancelled.")
            return
    else:
        confirm = input("\nContinue with migration? (y/N): ")
        if confirm.lower() != 'y':
            print("❌ Migration cancelled.")
            return
    
    print("\n" + "="*50)
    
    # Step 1: Drop all existing tables
    print("Step 1: Dropping all existing tables...")
    if not drop_all_tables():
        print("❌ Migration failed at drop step!")
        return
    
    print("\n" + "-"*30)
    
    # Step 2: Create all tables from models
    print("Step 2: Creating all tables from models...")
    if not create_all_tables():
        print("❌ Migration failed at create step!")
        return
    
    print("\n" + "-"*30)
    
    # Step 3: Show table information
    print("Step 3: Showing created tables...")
    show_table_info()
    
    print("\n" + "-"*30)
    
    # Step 4: Create default admin user
    print("Step 4: Creating default admin user...")
    if not create_default_admin():
        print("⚠️  Warning: Failed to create admin user, but migration continued.")
        print("   You can create an admin user manually later using:")
        print("   POST /admin/register with admin_secret")
    
    print("\n" + "="*50)
    print("🎉 Complete database migration finished successfully!")
    print("Your database is now clean and ready to use.")
    print("\n📝 Default Admin Credentials:")
    print("   Username: admin")
    print("   Password: admin234")
    print("   Email: admin@comot.in")
    print("   Login URL: POST /admin/login")
    print("\n🚨 SECURITY WARNING:")
    print("   Please change the default admin password immediately!")
    print("   Default credentials should only be used for initial setup.")
    print("\n🔗 Available Admin Endpoints:")
    print("   POST /admin/login - Admin authentication")
    print("   GET /admin/users - Manage users")
    print("   GET /admin/stats - System statistics")
    print("   DELETE /admin/user/{id} - Delete users")
    print("   PUT /admin/user/{id}/role - Change user roles")

if __name__ == "__main__":
    main()