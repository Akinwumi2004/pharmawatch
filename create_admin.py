import getpass
import mysql.connector
from werkzeug.security import generate_password_hash
from config import Config


def create_admin():
    connection = None
    cursor = None

    try:
        username = input("Enter administrator username: ").strip()
        full_name = input("Enter administrator full name: ").strip()

        if not username or not full_name:
            print("Username and full name are required.")
            return

        password = getpass.getpass("Enter administrator password: ")
        confirm_password = getpass.getpass("Confirm password: ")

        if len(password) < 12:
            print("Password must contain at least 12 characters.")
            return

        if password != confirm_password:
            print("Passwords do not match.")
            return

        connection = mysql.connector.connect(
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
            database=Config.DB_NAME
        )

        cursor = connection.cursor()

        cursor.execute(
            "SELECT id FROM users WHERE username = %s",
            (username,)
        )

        if cursor.fetchone():
            print("That username already exists.")
            return

        password_hash = generate_password_hash(password)

        cursor.execute("""
            INSERT INTO users
                (username, password_hash, full_name, role)
            VALUES (%s, %s, %s, %s)
        """, (
            username,
            password_hash,
            full_name,
            "admin"
        ))

        connection.commit()

        print("Administrator account created successfully!")

    except mysql.connector.Error as error:
        print("Database error:", error)

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None and connection.is_connected():
            connection.close()


if __name__ == "__main__":
    create_admin()
