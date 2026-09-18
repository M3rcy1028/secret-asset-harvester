"""Representative adapters used by a multi-database reporting service."""

import aiomysql
import asyncpg
import jaydebeapi
import mysql.connector
import peewee
import psycopg2
import pymongo
import pymssql
import pymysql
import pyodbc
import sqlalchemy
from aiopg import connect as aiopg_connect


HOST = "catalog.demo.internal"
PASSWORD = "fake-catalog-password"


def open_mysql_adapters():
    return [
        aiomysql.connect(host=HOST, password=PASSWORD),
        mysql.connector.connect(host=HOST, password=PASSWORD),
        pymysql.connect(host=HOST, password=PASSWORD),
    ]


def open_postgres_adapters():
    return [
        aiopg_connect(dsn="postgresql://reporter:fake-aiopg-password@catalog.demo.internal/catalog"),
        asyncpg.connect(host=HOST, password=PASSWORD),
        psycopg2.connect("postgresql://reporter:fake-psycopg-password@catalog.demo.internal/catalog"),
    ]


def open_other_adapters():
    return [
        pymongo.MongoClient(host=HOST, password=PASSWORD),
        pymssql.connect(server=HOST, password=PASSWORD),
        pyodbc.connect("Driver={SQL Server};Server=catalog.demo.internal;Database=catalog;Uid=reporter;Pwd=fake-pyodbc-password;"),
        jaydebeapi.connect("org.postgresql.Driver", "jdbc:postgresql://catalog.demo.internal:5432/catalog?user=reporter&password=fake-jaydebeapi-password"),
        peewee.PostgresqlDatabase("catalog", host=HOST, password=PASSWORD),
        sqlalchemy.create_engine("mysql://reporter:fake-sqlalchemy-password@catalog.demo.internal/catalog"),
    ]
