"""Application startup loading database settings in common config formats."""

import json
from pathlib import Path
from xml.etree import ElementTree

import aiomysql
import pymongo
import pymysql
import yaml


BASE_DIR = Path(__file__).parent


def load_mysql_config() -> dict:
    with open(BASE_DIR / "config.yaml", encoding="utf-8") as handle:
        mysql_config = yaml.safe_load(handle)
    return mysql_config


def connect_mysql():
    mysql_config = load_mysql_config()
    return aiomysql.connect(
        host=mysql_config["mysql"]["host"],
        password=mysql_config["mysql"]["password"],
        db=mysql_config["mysql"]["database"],
    )


def connect_postgres():
    with open(BASE_DIR / "config.json", encoding="utf-8") as handle:
        postgres_config = json.load(handle)
    return pymysql.connect(
        host=postgres_config["postgres"]["host"],
        password=postgres_config["postgres"]["password"],
        database=postgres_config["postgres"]["database"],
    )


def connect_document_store():
    root = ElementTree.parse(BASE_DIR / "config.xml").getroot()
    return pymongo.MongoClient(
        host=root.findtext("host"),
        password=root.findtext("password"),
    )
