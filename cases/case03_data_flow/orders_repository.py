"""Repository layer used by a scheduled order synchronization job."""

import asyncpg
import pymysql


MYSQL_SETTINGS = {
    "host": "mysql-orders.demo.internal",
    "password": "fake-orders-password",
    "database": "orders",
}


def open_mysql_pool():
    return pymysql.connect(
        host=MYSQL_SETTINGS["host"],
        password=MYSQL_SETTINGS["password"],
        database=MYSQL_SETTINGS["database"],
    )


def open_payment_pool():
    payment_host = "payments.demo.internal"
    payment_password = "fake-payments-password"
    return asyncpg.connect(payment_host, 5432, "payments_worker", payment_password, "payments")
