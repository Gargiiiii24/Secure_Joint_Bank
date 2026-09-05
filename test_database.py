from database import get_connection

print("Connecting to MySQL...")

try:
    connection = get_connection()

    print("MYSQL CONNECTION SUCCESSFUL!")

    cursor = connection.cursor()

    cursor.execute("SHOW TABLES")

    print("\nTables:")

    for table in cursor.fetchall():
        print("-", list(table.values())[0])

    cursor.close()
    connection.close()

    print("\nConnection closed.")

except Exception as e:
    print("DATABASE CONNECTION FAILED!")
    print("ERROR:", e)