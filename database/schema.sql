-- SmartBoard Residence database
-- MySQL Workbench: File > Open SQL Script... > pick this file > click the lightning bolt.
-- (Or run:  npm run setup)

CREATE DATABASE IF NOT EXISTS smartboard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smartboard;

CREATE TABLE IF NOT EXISTS rooms (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  room_no   VARCHAR(20)   NOT NULL UNIQUE,
  floor     TINYINT UNSIGNED NOT NULL DEFAULT 1,
  rent      DECIMAL(10,2) NOT NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS tenants (
  id        INT AUTO_INCREMENT PRIMARY KEY,
  name      VARCHAR(120)  NOT NULL,
  phone     VARCHAR(40)   NOT NULL DEFAULT '',
  contact   VARCHAR(160)  NOT NULL DEFAULT '',          -- emergency contact
  room_id   INT           NOT NULL,
  move_in   DATE          NOT NULL,
  move_out  DATE          NULL,                          -- NULL = still staying
  FOREIGN KEY (room_id) REFERENCES rooms(id),
  INDEX (room_id, move_out)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS users (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  username       VARCHAR(40)  NOT NULL UNIQUE,
  password_hash  VARCHAR(100) NOT NULL,                 -- bcrypt, never the real password
  full_name      VARCHAR(120) NOT NULL,
  role           ENUM('owner','staff','tenant') NOT NULL,
  tenant_id      INT NULL,                               -- links a tenant login to a tenant record
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS ledger (                     -- every payment, deposit, advance, refund
  id          INT AUTO_INCREMENT PRIMARY KEY,
  tenant_id   INT NOT NULL,
  bill_month  CHAR(7) NOT NULL,                          -- 'YYYY-MM'
  amount      DECIMAL(10,2) NOT NULL,
  paid_on     DATE NOT NULL,
  type        ENUM('rent','advance','deposit','apply','refund') NOT NULL,
  note        VARCHAR(255) NOT NULL DEFAULT '',
  FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE,
  INDEX (tenant_id, bill_month)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS readings (                   -- monthly electricity + water meter readings
  id          INT AUTO_INCREMENT PRIMARY KEY,
  room_id     INT NOT NULL,
  bill_month  CHAR(7) NOT NULL,
  prev_elec   DECIMAL(10,2) NOT NULL,
  curr_elec   DECIMAL(10,2) NOT NULL,
  prev_water  DECIMAL(10,2) NOT NULL,
  curr_water  DECIMAL(10,2) NOT NULL,
  UNIQUE KEY one_reading_per_month (room_id, bill_month),
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS misc_charges (               -- extra one-off charges added to a room's bill
  id          INT AUTO_INCREMENT PRIMARY KEY,
  room_id     INT NOT NULL,
  bill_month  CHAR(7) NOT NULL,
  description VARCHAR(160) NOT NULL,
  amount      DECIMAL(10,2) NOT NULL,
  FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
  INDEX (room_id, bill_month)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS rates (                      -- price per kWh / m3 / fixed fees, by effective month
  id               INT AUTO_INCREMENT PRIMARY KEY,
  type             ENUM('elec','water','wifi','garbage') NOT NULL,
  rate_value       DECIMAL(10,2) NOT NULL,
  effective_month  CHAR(7) NOT NULL,
  INDEX (type, effective_month)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS expenses (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  spent_on    DATE NOT NULL,
  category    VARCHAR(60)  NOT NULL,
  description VARCHAR(200) NOT NULL DEFAULT '',
  amount      DECIMAL(10,2) NOT NULL
) ENGINE=InnoDB;
