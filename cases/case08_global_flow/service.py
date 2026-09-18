"""Service factory where request settings cross a function boundary."""

import pymysql


def build_database_options(environment: str) -> tuple[str, str]:
    if environment == "production":
        host = "production-orders.demo.internal"
        password = "fake-production-password"
    else:
        host = "staging-orders.demo.internal"
        password = "fake-staging-password"
    return host, password


def create_connection(environment: str):
    host, password = build_database_options(environment)
    return pymysql.connect(host=host, password=password, database="orders")


def start_worker() -> None:
    create_connection("staging")
