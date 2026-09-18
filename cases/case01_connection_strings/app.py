"""A small order-import worker with production-style database URLs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ImportJob:
    name: str
    connection_url: str


JOBS = [
    ImportJob("orders", "mysql://etl:fake-mysql-password@mysql.demo.internal:3306/orders"),
    ImportJob("billing", "postgresql://etl:fake-postgres-password@postgres.demo.internal/billing"),
    ImportJob("events", "mongodb://etl:fake-mongo-password@mongo.demo.internal/events"),
]

WAREHOUSE_ODBC = "Driver={SQL Server};Server=warehouse.demo.internal;Port=1433;Database=warehouse;Uid=etl;Pwd=fake-odbc-password;"
REPORTING_OLEDB = "Provider=SQLOLEDB;Data Source=sql.demo.internal;Initial Catalog=reporting;User Id=etl;Password=fake-oledb-password;"
JDBC_URL = "jdbc:postgresql://jdbc.demo.internal:5432/analytics?user=etl&password=fake-jdbc-password"
JDBC_REPORTING_URL = "jdbc:sqlserver://jdbc-sql.demo.internal:1433/reporting?user=etl&password=fake-jdbc-sql-password"


def configured_jobs() -> list[ImportJob]:
    return JOBS
