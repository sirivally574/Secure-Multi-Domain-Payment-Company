import sqlite3
from security import hash_password

DATABASE = "securepayx.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    # Users
    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            balance REAL NOT NULL DEFAULT 10000.00,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Transactions
    connection.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE NOT NULL,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            amount REAL NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Security events
    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            event_type TEXT NOT NULL,
            description TEXT NOT NULL,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create demo admin account
    admin = connection.execute(
        "SELECT id FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if not admin:
        connection.execute(
            """
            INSERT INTO users
            (username, password_hash, role, balance)
            VALUES (?, ?, ?, ?)
            """,
            (
                "admin",
                hash_password("SecurePay@Admin123"),
                "admin",
                100000.00
            )
        )

    connection.commit()
    connection.close()


def create_user(username, password):
    connection = get_connection()

    try:
        connection.execute(
            """
            INSERT INTO users
            (username, password_hash, role, balance)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                hash_password(password),
                "customer",
                10000.00
            )
        )

        connection.commit()
        return True

    except sqlite3.IntegrityError:
        return False

    finally:
        connection.close()


def get_user(username):
    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    connection.close()

    return user


def get_all_users():
    connection = get_connection()

    users = connection.execute(
        """
        SELECT id, username, role, balance, created_at
        FROM users
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return users


def update_balance(username, new_balance):
    connection = get_connection()

    connection.execute(
        """
        UPDATE users
        SET balance = ?
        WHERE username = ?
        """,
        (new_balance, username)
    )

    connection.commit()
    connection.close()


def add_transaction(
    transaction_id,
    sender,
    recipient,
    amount,
    risk_score,
    status
):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO transactions
        (
            transaction_id,
            sender,
            recipient,
            amount,
            risk_score,
            status
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            transaction_id,
            sender,
            recipient,
            amount,
            risk_score,
            status
        )
    )

    connection.commit()
    connection.close()


def get_user_transactions(username):
    connection = get_connection()

    transactions = connection.execute(
        """
        SELECT *
        FROM transactions
        WHERE sender = ?
        OR recipient = ?
        ORDER BY id DESC
        """,
        (username, username)
    ).fetchall()

    connection.close()

    return transactions


def get_all_transactions():
    connection = get_connection()

    transactions = connection.execute(
        """
        SELECT *
        FROM transactions
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return transactions


def add_security_event(
    username,
    event_type,
    description,
    ip_address
):
    connection = get_connection()

    connection.execute(
        """
        INSERT INTO security_events
        (
            username,
            event_type,
            description,
            ip_address
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            username,
            event_type,
            description,
            ip_address
        )
    )

    connection.commit()
    connection.close()


def get_security_events(limit=30):
    connection = get_connection()

    events = connection.execute(
        """
        SELECT *
        FROM security_events
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,)
    ).fetchall()

    connection.close()

    return events


def get_statistics():
    connection = get_connection()

    total_users = connection.execute(
        "SELECT COUNT(*) FROM users"
    ).fetchone()[0]

    total_transactions = connection.execute(
        "SELECT COUNT(*) FROM transactions"
    ).fetchone()[0]

    successful_payments = connection.execute(
        """
        SELECT COUNT(*)
        FROM transactions
        WHERE status = 'APPROVED'
        """
    ).fetchone()[0]

    blocked_payments = connection.execute(
        """
        SELECT COUNT(*)
        FROM transactions
        WHERE status = 'BLOCKED'
        """
    ).fetchone()[0]

    security_events = connection.execute(
        "SELECT COUNT(*) FROM security_events"
    ).fetchone()[0]

    connection.close()

    return {
        "total_users": total_users,
        "total_transactions": total_transactions,
        "successful_payments": successful_payments,
        "blocked_payments": blocked_payments,
        "security_events": security_events
    }