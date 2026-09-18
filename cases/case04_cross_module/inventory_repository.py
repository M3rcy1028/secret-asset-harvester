"""Inventory repository imported by the application service."""

import pymysql

from settings import DATABASE_HOST, DATABASE_NAME, DATABASE_PASSWORD


def connect_inventory():
    return pymysql.connect(
        host=DATABASE_HOST,
        password=DATABASE_PASSWORD,
        database=DATABASE_NAME,
    )
