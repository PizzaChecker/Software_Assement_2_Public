-- Drop existing tables if they exist
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS privileges;

-- Create the users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE, -- Unique username for each user
    hashed_password TEXT NOT NULL, -- Hashed password for security
    mobile TEXT NOT NULL,
    address TEXT NOT NULL,
    security_question_1 TEXT NOT NULL,
    security_answer_1 TEXT NOT NULL,
    security_question_2 TEXT NOT NULL,
    security_answer_2 TEXT NOT NULL,
    image_path TEXT NOT NULL,
    privilege_id INTEGER NOT NULL, -- Foreign key to privileges table
    FOREIGN KEY (privilege_id) REFERENCES privileges(id) -- Reference to privileges table
);

-- Create the privileges table
CREATE TABLE privileges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    privilege_name TEXT NOT NULL UNIQUE -- Unique name for each privilege
);

INSERT INTO privileges (privilege_name)
VALUES 
('user'),
('admin');