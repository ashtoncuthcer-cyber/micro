-- CREATE USER 'auth_user'@'%' IDENTIFIED BY 'Aauth123';
-- CREATE DATABASE IF NOT EXISTS auth;
-- GRANT ALL PRIVILEGES ON auth.* TO 'auth_user'@'%';
-- FLUSH PRIVILEGES;

USE auth;

CREATE TABLE IF NOT EXISTS user (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL
);

INSERT INTO user (email, password) VALUES ('test@email.com', 'test');