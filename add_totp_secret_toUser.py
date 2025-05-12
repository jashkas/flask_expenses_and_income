from app import db, app  # Import 'app' instead of 'create_app'
from models import User  # Import your User model

def add_totp_column():
    # For SQLite (works with other databases too)
    from sqlalchemy import text
    
    try:
        # Check if column exists
        with db.engine.connect() as conn:
            conn.execute(text("SELECT totp_secret FROM user LIMIT 1"))
    except Exception as e:
        # If column doesn't exist, add it
        print(f"Column doesn't exist, adding it. Error: {e}")
        with db.engine.connect() as conn:
            conn.execute(text("ALTER TABLE user ADD COLUMN totp_secret VARCHAR(32)"))
            conn.commit()
        print("Column 'totp_secret' added successfully")
    else:
        print("Column 'totp_secret' already exists")

if __name__ == '__main__':
    with app.app_context():  # Use app context
        add_totp_column()