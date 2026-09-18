const mysql = require("mysql2");

function createOrdersPool() {
  return mysql.createPool({
    host: process.env.DB_HOST,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
}

module.exports = { createOrdersPool };
