"""Health endpoint with nearby non-database endpoints and credentials."""

import pymysql


FILE_STORAGE_HOST = "files.demo.internal"
MYSQL_HOST = "mysql-health.demo.internal"
MYSQL_PASSWORD = "fake-health-password"


def check_dependencies() -> bool:
    pymysql.connect(host=MYSQL_HOST, password=MYSQL_PASSWORD, database="health")
    return bool(FILE_STORAGE_HOST)
