import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "data" / "portal.db"


def create_academic_records_table(
    cursor
):
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS academic_records (
            id INTEGER PRIMARY KEY,
            student_code TEXT NOT NULL,
            course TEXT NOT NULL,
            grade REAL NOT NULL,
            updated_by TEXT NOT NULL
        )
        """
    )


def reset_academic_records():
    connection = sqlite3.connect(
        DB_FILE
    )

    cursor = connection.cursor()

    create_academic_records_table(
        cursor
    )

    cursor.execute(
        """
        DELETE FROM academic_records
        """
    )

    cursor.execute(
        """
        INSERT INTO academic_records (
            id,
            student_code,
            course,
            grade,
            updated_by
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            1,
            "EST-001",
            "Seguridad Informática",
            4.5,
            "sistema"
        )
    )

    connection.commit()
    connection.close()


def init_database():
    DB_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(
        DB_FILE
    )

    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )
        """
    )

    users = [
        (
            "estudiante",
            "Demo-2026",
            "STUDENT"
        ),
        (
            "admin_lab",
            "Admin-CR-2026",
            "ADMIN"
        )
    ]

    for username, password, role in users:

        cursor.execute(
            """
            INSERT OR IGNORE INTO users (
                username,
                password,
                role
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                password,
                role
            )
        )

    create_academic_records_table(
        cursor
    )

    existing_record = cursor.execute(
        """
        SELECT id
        FROM academic_records
        WHERE id = 1
        """
    ).fetchone()

    if not existing_record:

        cursor.execute(
            """
            INSERT INTO academic_records (
                id,
                student_code,
                course,
                grade,
                updated_by
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                1,
                "EST-001",
                "Seguridad Informática",
                4.5,
                "sistema"
            )
        )

    connection.commit()
    connection.close()

    print(
        f"Base del portal inicializada: {DB_FILE}"
    )

def restore_academic_record():
    connection = sqlite3.connect(
        DB_FILE
    )

    cursor = connection.cursor()

    create_academic_records_table(
        cursor
    )

    cursor.execute(
        """
        UPDATE academic_records
        SET grade = ?,
            updated_by = ?
        WHERE id = ?
        """,
        (
            4.5,
            "IR_LEAD_RESTORE",
            1
        )
    )

    connection.commit()
    connection.close()

if __name__ == "__main__":
    init_database()
