"""HTTP-style webhook handler that opens a reporting connection."""

import mysql.connector


def handle_webhook(payload: dict[str, str]) -> dict[str, int]:
    connection = mysql.connector.connect(
        host=payload.get("db_host", "webhook.demo.internal"),
        password=payload.get("db_password", "fake-webhook-password"),
        database="webhooks",
    )
    cursor = connection.cursor()
    cursor.execute("INSERT INTO deliveries (event_id) VALUES (%s)", (payload["id"],))
    connection.commit()
    return {"status": 202}


def handle_batch(payload: dict[str, str]) -> None:
    mysql.connector.connect(**{"host": "batch.demo.internal", "password": "fake-batch-password", "database": "batch"})
