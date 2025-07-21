from sql_database import SessionLocal, User
from datetime import datetime, timezone
from cryptography.fernet import Fernet
import base64

with open("Encryption_key.txt", "rb") as l:
    key = l.read().strip()
cipher = Fernet(key)
del key
def encrypt_txt(txt):
    return cipher.encrypt(txt.encode()).decode()
def add_fake_user():
    session = SessionLocal()

    # Create a fake user with a simple string ID
    fake_user = User(
        id="user123",  # Replace with any unique string ID you want
        first_name=encrypt_txt("John"),
        last_name=encrypt_txt("Doe"),
        approved="no",
        created_at=datetime.now(timezone.utc)
    )

    session.add(fake_user)
    session.commit()
    session.close()



def remove_user(user_id):
    session = SessionLocal()
    # Find the user by id
    user = session.query(User).filter_by(id=user_id).first()

    if user:
        session.delete(user)
        session.commit()
        print(f"User with id '{user_id}' has been removed.")
    else:
        print(f"No user found with id '{user_id}'.")


if __name__ == "__main__":
    remove_user("user123")
