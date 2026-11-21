"""SQLite connection handling and the `init-db` CLI command."""
import sqlite3
from pathlib import Path

import click
from flask import current_app, g
from flask.cli import with_appcontext

SCHEMA_FILE = Path(__file__).with_name("schema.sql")


def get_db():
    """Return one SQLite connection per request (stored on flask.g)."""
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(seed=True):
    """Drop and recreate all tables, then optionally load the sample data."""
    conn = get_db()
    conn.executescript(SCHEMA_FILE.read_text(encoding="utf-8"))
    conn.commit()
    if seed:
        from .seed import seed_database

        return seed_database(conn)
    return None


@click.command("init-db")
@with_appcontext
def init_db_command():
    """Reset the database: recreate the schema and load the sample data."""
    summary = init_db(seed=True)
    click.echo(f"Database ready: {current_app.config['DATABASE']}")
    click.echo(f"  users:    {summary['users']}  {summary['roles']}")
    click.echo(f"  bookings: {summary['bookings']}")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
