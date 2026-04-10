-- MYSQL SETUP for Casa Monarca Django project
-- Adjust the password before running.

CREATE DATABASE IF NOT EXISTS casamonarca CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'casamonarca_user'@'localhost' IDENTIFIED BY 'Cm2026MySQL!';
GRANT ALL PRIVILEGES ON casamonarca.* TO 'casamonarca_user'@'localhost';
FLUSH PRIVILEGES;
