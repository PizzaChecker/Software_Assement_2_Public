import sqlite3

def init_db():
    try:
        # Establish a connection to the SQLite database
        connection = sqlite3.connect('database.db')

        # Use a context manager to ensure the file is properly closed
        with open('schema.sql', 'r') as f:
            connection.executescript(f.read())
        
        connection.commit()
        print("Database initialised successfully.")

    except sqlite3.Error as e:
        print(f"An error occurred: {e}") #Change in future
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

    finally:
        # Ensure the connection is closed
        if connection:
            connection.close()

if __name__ == '__main__':#Make it so it also adds the user Admin here:
    init_db()