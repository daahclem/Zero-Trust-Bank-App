CREATE DATABASE zerotrust;
GRANT ALL PRIVILEGES ON zerotrust.* TO 'root'@'localhost' IDENTIFIED BY '1234Kwadwo';
USE zerotrust;

CREATE TABLE LoginAccounts (
    username VARCHAR(255) PRIMARY KEY,
    password VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    firstName VARCHAR(255),
    lastName VARCHAR(255),
    address VARCHAR(255),
    phoneNumber VARCHAR(255)
);

CREATE TABLE BalanceAccount (
    username VARCHAR(255) PRIMARY KEY,
    amount FLOAT(12),
    FOREIGN KEY (username) REFERENCES LoginAccounts(username)
);
CREATE TABLE Transactions (
    transaction_id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    transaction_type ENUM('deposit', 'withdrawal', 'transfer'),
    amount FLOAT(12),
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (username) REFERENCES LoginAccounts(username)
);


CREATE TABLE IF NOT EXISTS Accounts (
    account_id INT AUTO_INCREMENT PRIMARY KEY,
    account_name VARCHAR(255) NOT NULL,
    account_number VARCHAR(255) NOT NULL,
    username VARCHAR(255)
);
ALTER TABLE LoginAccounts
ADD INDEX idx_username (username);
ALTER TABLE Accounts
ADD FOREIGN KEY (username) REFERENCES LoginAccounts(username);


CREATE TABLE Roles (
    role_id INT AUTO_INCREMENT PRIMARY KEY,
    role_name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE UserRoles (
    username VARCHAR(255),
    role_id INT,
    FOREIGN KEY (username) REFERENCES LoginAccounts(username),
    FOREIGN KEY (role_id) REFERENCES Roles(role_id)
);
CREATE TABLE UserActivityLogs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    method VARCHAR(10),
    url VARCHAR(255),
    timestamp DATETIME
);
CREATE TABLE UserActivityLogs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    method VARCHAR(10),
    url VARCHAR(255),
    timestamp DATETIME
);

CREATE TABLE UserNetworkResources (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    resource_name VARCHAR(255),
    FOREIGN KEY (username) REFERENCES LoginAccounts(username)
);
